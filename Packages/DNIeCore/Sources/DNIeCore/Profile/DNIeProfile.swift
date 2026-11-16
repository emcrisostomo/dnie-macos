import CryptoKit
import Foundation

public enum DNIeProfileError: Error, Sendable, Equatable {
    case unsupportedProfile
    case capabilityDisabled
    case cardStatus(CardStatus)
    case invalidFileControlInformation
    case shortRead
}

public struct DNIePublicDiscovery: Sendable, Equatable {
    public let opaqueInstanceInput: Data
    public let certificates: [PKCS15ObjectReference]
    public let privateKeys: [PKCS15ObjectReference]
    public let certificateFiles: [DNIeDiscoveredCertificate]

    public init(
        opaqueInstanceInput: Data,
        certificates: [PKCS15ObjectReference],
        privateKeys: [PKCS15ObjectReference],
        certificateFiles: [DNIeDiscoveredCertificate]
    ) {
        self.opaqueInstanceInput = opaqueInstanceInput
        self.certificates = certificates
        self.privateKeys = privateKeys
        self.certificateFiles = certificateFiles
    }
}

public struct DNIeDiscoveredCertificate: Sendable, Equatable {
    public let reference: PKCS15ObjectReference
    public let file: ValidatedCertificateFile

    public init(reference: PKCS15ObjectReference, file: ValidatedCertificateFile) {
        self.reference = reference
        self.file = file
    }
}

public struct DNIeProfile: CardProfile {
    public static let applicationSelector = Data([
        0xA0, 0x00, 0x00, 0x00, 0x63, 0x50,
        0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35,
    ])

    private static let certificateDirectoryPath: [UInt16] = [0x3F00, 0x5015, 0x6004]
    private static let privateKeyDirectoryPath: [UInt16] = [0x3F00, 0x5015, 0x6001]
    private static let instanceDomain = Data("org.dniemacos.public-instance/v1\0".utf8)
    private static let success = CardStatus(first: 0x90, second: 0x00)
    private static let maximumReadLength = 255

    // Public, reviewed observations only. This is the canonical version-1 input to
    // EvidenceManifest; private-channel capabilities have no mapping here.
    private static let reviewedEvidenceRecords = Data(#"""
    [
      {"evidence_id":"E-DNIE-U03-AID","claim":"The target selects the documented PKCS15 application with the exact configured AID","state":"EXPERIMENTALLY VERIFIED","experiment_id":"U-03","decision_impact":"Enables exact application recognition","review_date":"2026-08-23"},
      {"evidence_id":"E-DNIE-U07-CHIP-INFO","claim":"The target returns the documented seven-byte GET CHIP INFO response shape","state":"EXPERIMENTALLY VERIFIED","experiment_id":"U-07","decision_impact":"Enables opaque instance input derivation","review_date":"2026-08-22"},
      {"evidence_id":"E-DNIE-U04-CDF","claim":"The target exposes bounded public certificate directory and certificate containers through card-provided paths","state":"EXPERIMENTALLY VERIFIED","experiment_id":"U-04","decision_impact":"Enables public certificate discovery","review_date":"2026-08-23"},
      {"evidence_id":"E-DNIE-U04C-PRKDF","claim":"The target exposes bounded private key metadata through the documented PrKDF path","state":"EXPERIMENTALLY VERIFIED","experiment_id":"U-04C","decision_impact":"Enables public key-reference discovery only","review_date":"2026-08-23"}
    ]
    """#.utf8)
    private static let capabilityEvidenceIDs: [ProfileCapability: [String]] = [
        .recognize: ["E-DNIE-U03-AID"],
        .instance: ["E-DNIE-U03-AID", "E-DNIE-U07-CHIP-INFO"],
        .discover: ["E-DNIE-U04-CDF", "E-DNIE-U04C-PRKDF"],
    ]

    public let descriptor: CardProfileDescriptor
    private let directoryReader: PKCS15DirectoryReader
    private let certificateDecoder: CertificateFileDecoder

    public init() {
        self.init(evidenceRecords: Self.reviewedEvidenceRecords)
    }

    // Internal injection permits a fail-closed malformed-input test. Runtime callers
    // cannot supply their own records or capability mapping.
    init(evidenceRecords: Data) {
        let gate = (try? EvidenceManifest.load(
            version: "1",
            evidenceRecords: evidenceRecords,
            capabilityEvidenceIDs: Self.capabilityEvidenceIDs
        ).capabilityGate) ?? CapabilityGate(requirements: [:])
        descriptor = CardProfileDescriptor(
            profileID: "org.dniemacos.dnie.generation2",
            version: ProfileVersion("1"),
            applicationSelector: Self.applicationSelector,
            capabilityGate: gate,
            limits: ProfileLimits(
                maximumCommandLength: CardTransportRequest.maximumCommandLength,
                maximumResponseLength: CardTransportRequest.maximumResponseLength,
                maximumDirectoryLength: 16 * 1_024,
                maximumCertificateLength: 32 * 1_024
            )
        )
        directoryReader = PKCS15DirectoryReader()
        certificateDecoder = CertificateFileDecoder()
    }

    public func discover(
        selectedApplication: Data,
        transport: any CardTransport,
        generation: ConnectionGeneration
    ) async throws -> DNIePublicDiscovery {
        guard recognizes(selectedApplication: selectedApplication) else {
            throw DNIeProfileError.unsupportedProfile
        }
        guard isEnabled(.instance), isEnabled(.discover) else {
            throw DNIeProfileError.capabilityDisabled
        }

        let chipInformation = try await exchange(
            kind: .getChipInformation,
            command: CardStructuredCommand(
                cla: 0x90,
                instruction: 0xB8,
                p1: 0x00,
                p2: 0x00,
                expectedResponseLength: 7
            ),
            maximumResponseLength: 7,
            transport: transport,
            generation: generation
        )
        guard chipInformation.count == 7 else {
            throw DNIeProfileError.shortRead
        }
        var instanceMaterial = Self.instanceDomain
        instanceMaterial.append(chipInformation)
        let opaqueInstanceInput = Data(SHA256.hash(data: instanceMaterial))

        let cdf = try await readDirectory(
            path: Self.certificateDirectoryPath,
            transport: transport,
            generation: generation
        )
        let prkdf = try await readDirectory(
            path: Self.privateKeyDirectoryPath,
            transport: transport,
            generation: generation
        )
        let certificateReferences = try directoryReader.certificateObjects(from: cdf).objects
        var certificateFiles: [DNIeDiscoveredCertificate] = []
        for reference in certificateReferences {
            certificateFiles.append(DNIeDiscoveredCertificate(
                reference: reference,
                file: try await readCertificate(
                    reference: reference,
                    transport: transport,
                    generation: generation
                )
            ))
        }
        return DNIePublicDiscovery(
            opaqueInstanceInput: opaqueInstanceInput,
            certificates: certificateReferences,
            privateKeys: try directoryReader.privateKeyObjects(from: prkdf).objects,
            certificateFiles: certificateFiles
        )
    }

    private func readCertificate(
        reference: PKCS15ObjectReference,
        transport: any CardTransport,
        generation: ConnectionGeneration
    ) async throws -> ValidatedCertificateFile {
        let allocation = try await select(
            path: reference.path.components,
            transport: transport,
            generation: generation
        )
        let header = try await readCurrentFile(
            length: 8,
            transport: transport,
            generation: generation
        )
        let containerLength = try certificateDecoder.declaredContainerLength(
            header: header,
            allocatedFileLength: allocation
        )
        let container = try await readCurrentFile(
            length: containerLength,
            transport: transport,
            generation: generation
        )
        return try certificateDecoder.decode(
            container: container,
            allocatedFileLength: allocation
        )
    }

    private func readDirectory(
        path: [UInt16],
        transport: any CardTransport,
        generation: ConnectionGeneration
    ) async throws -> Data {
        let length = try await select(
            path: path,
            transport: transport,
            generation: generation
        )
        guard length <= descriptor.limits.maximumDirectoryLength else {
            throw DNIeProfileError.invalidFileControlInformation
        }
        return try await readCurrentFile(
            length: length,
            transport: transport,
            generation: generation
        )
    }

    private func select(
        path: [UInt16],
        transport: any CardTransport,
        generation: ConnectionGeneration
    ) async throws -> Int {
        let absolutePath = path.first == 0x3F00 ? path : [0x3F00] + path
        var controlInformation = Data()
        for component in absolutePath {
            controlInformation = try await exchange(
                kind: .select,
                command: CardStructuredCommand(
                    cla: 0x00,
                    instruction: 0xA4,
                    p1: 0x00,
                    p2: 0x00,
                    data: Data([UInt8(component >> 8), UInt8(component & 0xFF)]),
                    expectedResponseLength: 0
                ),
                maximumResponseLength: 256,
                transport: transport,
                generation: generation
            )
        }
        return try allocatedLength(from: controlInformation)
    }

    private func readCurrentFile(
        length: Int,
        transport: any CardTransport,
        generation: ConnectionGeneration
    ) async throws -> Data {
        var directory = Data()
        directory.reserveCapacity(length)
        while directory.count < length {
            let offset = directory.count
            let count = min(Self.maximumReadLength, length - offset)
            let chunk = try await exchange(
                kind: .readBinary,
                command: CardStructuredCommand(
                    cla: 0x00,
                    instruction: 0xB0,
                    p1: UInt8((offset >> 8) & 0x7F),
                    p2: UInt8(offset & 0xFF),
                    expectedResponseLength: count
                ),
                maximumResponseLength: count,
                transport: transport,
                generation: generation
            )
            guard chunk.count == count else {
                throw DNIeProfileError.shortRead
            }
            directory.append(chunk)
        }
        return directory
    }

    private func exchange(
        kind: CardTransportCommandKind,
        command: CardStructuredCommand,
        maximumResponseLength: Int,
        transport: any CardTransport,
        generation: ConnectionGeneration
    ) async throws -> Data {
        let response = try await transport.transmit(
            CardTransportRequest(
                kind: kind,
                structuredCommand: command,
                maximumResponseLength: maximumResponseLength
            ),
            generation: generation,
            correlationID: CorrelationID()
        )
        guard response.status == Self.success else {
            throw DNIeProfileError.cardStatus(response.status)
        }
        return response.data
    }

    private func allocatedLength(from fci: Data) throws -> Int {
        let matches = try findValues(tag: 0x85, in: [UInt8](fci), depth: 4)
        guard matches.count == 1, let value = matches.first, value.count >= 5 else {
            throw DNIeProfileError.invalidFileControlInformation
        }
        let length = Int(value[3]) << 8 | Int(value[4])
        guard length > 0 else {
            throw DNIeProfileError.invalidFileControlInformation
        }
        return length
    }

    private func findValues(
        tag soughtTag: UInt8,
        in bytes: [UInt8],
        depth: Int
    ) throws -> [[UInt8]] {
        guard depth >= 0 else { return [] }
        var offset = 0
        var matches: [[UInt8]] = []
        while offset < bytes.count {
            guard offset + 2 <= bytes.count else {
                throw DNIeProfileError.invalidFileControlInformation
            }
            let tag = bytes[offset]
            offset += 1
            let firstLength = bytes[offset]
            offset += 1
            let length: Int
            if firstLength & 0x80 == 0 {
                length = Int(firstLength)
            } else {
                let count = Int(firstLength & 0x7F)
                guard (1...2).contains(count), offset + count <= bytes.count else {
                    throw DNIeProfileError.invalidFileControlInformation
                }
                length = bytes[offset..<(offset + count)].reduce(0) {
                    $0 << 8 | Int($1)
                }
                offset += count
            }
            guard length <= bytes.count - offset else {
                throw DNIeProfileError.invalidFileControlInformation
            }
            let value = Array(bytes[offset..<(offset + length)])
            offset += length
            if tag == soughtTag {
                matches.append(value)
            }
            if depth > 0, tag & 0x20 != 0 {
                matches.append(contentsOf: try findValues(
                    tag: soughtTag,
                    in: value,
                    depth: depth - 1
                ))
            }
        }
        return matches
    }
}
