import Foundation
import Security

public enum ChannelAuthenticationError: Error, Sendable, Equatable {
    case invalidAuthentication
    case invalidCertificate
}

struct DNIeAuthenticationBlock {
    static func make(seed: Data, challenge: Data, serial: Data) throws -> Data {
        guard seed.count == 32, challenge.count == 8, serial.count == 8 else {
            throw ChannelAuthenticationError.invalidAuthentication
        }
        var random = try CryptoPrimitives.randomBytes(count: 62)
        var hashInput = random + seed + challenge + serial
        defer {
            CryptoPrimitives.secureZero(&random)
            CryptoPrimitives.secureZero(&hashInput)
        }
        return Data([0x6A])
            + random
            + seed
            + CryptoPrimitives.sha256(hashInput)
            + Data([0xBC])
    }

    static func recover(
        minimumSignature: Data,
        signer: RawRSAKey,
        challenge: Data,
        serial: Data
    ) throws -> Data {
        guard minimumSignature.count == signer.modulus.count,
              challenge.count == 8,
              serial.count == 8 else {
            throw ChannelAuthenticationError.invalidAuthentication
        }
        let complement = try FixedWidthUnsigned.subtract(
            signer.modulus,
            minimumSignature
        )
        for candidate in [minimumSignature, complement] {
            var block = try signer.publicOperation(candidate)
            defer { CryptoPrimitives.secureZero(&block) }
            guard block.count == 128,
                  block.first == 0x6A,
                  block.last == 0xBC else {
                continue
            }
            let hashStart = block.count - 33
            var hashInput = Data(block[1..<hashStart]) + challenge + serial
            defer { CryptoPrimitives.secureZero(&hashInput) }
            guard CryptoPrimitives.verifyTag(
                expected: Data(block[hashStart..<(block.count - 1)]),
                actual: CryptoPrimitives.sha256(hashInput)
            ) else {
                continue
            }
            return Data(block[(hashStart - 32)..<hashStart])
        }
        throw ChannelAuthenticationError.invalidAuthentication
    }
}

struct DNIeRSAPublicComponents: Sendable, Equatable {
    let modulus: Data
    let exponent: Data
}

enum DNIeComponentCertificateChain {
    static func verify(
        intermediate: Data,
        component: Data,
        rootModulus: Data,
        rootExponent: Data
    ) throws -> DNIeRSAPublicComponents {
        let root = try makePublicKey(
            modulus: rootModulus,
            exponent: rootExponent
        )
        let intermediateParts = try certificateParts(intermediate)
        guard SecKeyVerifySignature(
            root,
            intermediateParts.algorithm,
            intermediateParts.tbs as CFData,
            intermediateParts.signature as CFData,
            nil
        ) else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        guard let intermediateCertificate = SecCertificateCreateWithData(
            nil,
            intermediate as CFData
        ), let intermediateKey = SecCertificateCopyKey(intermediateCertificate) else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        let componentParts = try certificateParts(component)
        guard SecKeyVerifySignature(
            intermediateKey,
            componentParts.algorithm,
            componentParts.tbs as CFData,
            componentParts.signature as CFData,
            nil
        ) else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        guard let componentCertificate = SecCertificateCreateWithData(
            nil,
            component as CFData
        ), let componentKey = SecCertificateCopyKey(componentCertificate),
           SecKeyGetBlockSize(componentKey) == 128,
           let external = SecKeyCopyExternalRepresentation(componentKey, nil) as Data? else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        return try parseRSAPublicKey(external)
    }

    private static func certificateParts(_ certificate: Data) throws -> (
        tbs: Data,
        algorithm: SecKeyAlgorithm,
        signature: Data
    ) {
        let outerItems = try SecureMessagingTLV.parseAll(certificate)
        guard outerItems.count == 1, outerItems[0].tag == 0x30 else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        let items = try SecureMessagingTLV.parseAll(outerItems[0].value)
        guard items.count == 3,
              items[0].tag == 0x30,
              items[1].tag == 0x30,
              items[2].tag == 0x03,
              items[2].value.first == 0 else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        let algorithmItems = try SecureMessagingTLV.parseAll(items[1].value)
        guard let oid = algorithmItems.first, oid.tag == 0x06 else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        let algorithm: SecKeyAlgorithm
        switch oid.value {
        case Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]):
            algorithm = .rsaSignatureMessagePKCS1v15SHA1
        case Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]):
            algorithm = .rsaSignatureMessagePKCS1v15SHA256
        default:
            throw ChannelAuthenticationError.invalidCertificate
        }
        return (
            items[0].encoded,
            algorithm,
            Data(items[2].value.dropFirst())
        )
    }

    private static func makePublicKey(
        modulus: Data,
        exponent: Data
    ) throws -> SecKey {
        let representation = derSequence([
            derInteger(modulus),
            derInteger(exponent),
        ])
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: modulus.count * 8,
        ]
        guard let key = SecKeyCreateWithData(
            representation as CFData,
            attributes as CFDictionary,
            nil
        ) else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        return key
    }

    private static func parseRSAPublicKey(
        _ representation: Data
    ) throws -> DNIeRSAPublicComponents {
        let sequences = try SecureMessagingTLV.parseAll(representation)
        guard sequences.count == 1, sequences[0].tag == 0x30 else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        let integers = try SecureMessagingTLV.parseAll(sequences[0].value)
        guard integers.count == 2,
              integers[0].tag == 0x02,
              integers[1].tag == 0x02 else {
            throw ChannelAuthenticationError.invalidCertificate
        }
        return DNIeRSAPublicComponents(
            modulus: normalized(integers[0].value),
            exponent: normalized(integers[1].value)
        )
    }

    private static func derInteger(_ value: Data) -> Data {
        var value = normalized(value)
        if value[0] & 0x80 != 0 { value.insert(0, at: 0) }
        return Data([0x02]) + derLength(value.count) + value
    }

    private static func derSequence(_ values: [Data]) -> Data {
        let body = values.reduce(into: Data()) { $0.append($1) }
        return Data([0x30]) + derLength(body.count) + body
    }

    private static func derLength(_ count: Int) -> Data {
        if count < 0x80 { return Data([UInt8(count)]) }
        var value = count
        var output = Data()
        while value > 0 {
            output.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(output.count)]) + output
    }

    private static func normalized(_ value: Data) -> Data {
        let stripped = Data(value.drop(while: { $0 == 0 }))
        return stripped.isEmpty ? Data([0]) : stripped
    }
}
