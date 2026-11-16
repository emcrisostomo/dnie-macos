import CryptoKit
import Foundation

public struct CatalogCertificateCandidate: Sendable, Equatable {
    public let reference: PKCS15ObjectReference
    public let certificateDER: Data
    public let role: CertificateRole
    public let publicKeyRepresentation: Data

    public init(
        reference: PKCS15ObjectReference,
        certificateDER: Data,
        role: CertificateRole,
        publicKeyRepresentation: Data
    ) {
        precondition(reference.objectType == .certificate)
        precondition(!certificateDER.isEmpty)
        precondition(!publicKeyRepresentation.isEmpty)
        self.reference = reference
        self.certificateDER = certificateDER
        self.role = role
        self.publicKeyRepresentation = publicKeyRepresentation
    }
}

public struct CatalogPrivateKeyCandidate: Sendable, Equatable {
    public let reference: PKCS15ObjectReference
    public let publicKeyRepresentation: Data
    public let constraints: [CardOperationKind: Data]
    public let algorithms: Set<KeyAlgorithm>

    public init(
        reference: PKCS15ObjectReference,
        publicKeyRepresentation: Data,
        constraints: [CardOperationKind: Data],
        algorithms: Set<KeyAlgorithm>
    ) {
        precondition(reference.objectType == .privateKey)
        precondition(!publicKeyRepresentation.isEmpty)
        self.reference = reference
        self.publicKeyRepresentation = publicKeyRepresentation
        self.constraints = constraints
        self.algorithms = algorithms
    }
}

public enum CatalogExclusion: String, Hashable, Sendable {
    case duplicateIdentifier
    case noUniqueKeyMatch
    case ineligibleCertificateRole
    case publicKeyMismatch
}

public struct TokenCatalogBuildResult: Sendable, Equatable {
    public let identities: [DNIeIdentityDescriptor]
    public let supportingCertificates: [DNIeSupportingCertificateDescriptor]
    public let exclusionCounts: [CatalogExclusion: Int]

    public init(
        identities: [DNIeIdentityDescriptor],
        supportingCertificates: [DNIeSupportingCertificateDescriptor],
        exclusionCounts: [CatalogExclusion: Int]
    ) {
        self.identities = identities
        self.supportingCertificates = supportingCertificates
        self.exclusionCounts = exclusionCounts
    }
}

public struct TokenCatalogBuilder: Sendable {
    private static let objectIDDomain = Data("org.dniemacos.identity-object/v1\0".utf8)

    private let instanceID: Data
    private let allowedAlgorithms: Set<KeyAlgorithm>

    public init(instanceID: Data, allowedAlgorithms: Set<KeyAlgorithm>) {
        precondition(!instanceID.isEmpty)
        self.instanceID = instanceID
        self.allowedAlgorithms = allowedAlgorithms
    }

    public func build(
        certificates: [CatalogCertificateCandidate],
        privateKeys: [CatalogPrivateKeyCandidate]
    ) -> TokenCatalogBuildResult {
        let duplicateCertificateIDs = duplicateIDs(certificates.map(\.reference.ckaID))
        let duplicateKeyIDs = duplicateIDs(privateKeys.map(\.reference.ckaID))
        var identities: [DNIeIdentityDescriptor] = []
        var supportingCertificates: [DNIeSupportingCertificateDescriptor] = []
        var exclusions: [CatalogExclusion: Int] = [:]

        for certificate in certificates {
            if certificate.role == .intermediate {
                guard !duplicateCertificateIDs.contains(certificate.reference.ckaID) else {
                    count(.duplicateIdentifier, in: &exclusions)
                    continue
                }
                supportingCertificates.append(DNIeSupportingCertificateDescriptor(
                    objectID: objectID(
                        for: certificate.reference.ckaID,
                        role: certificate.role
                    ),
                    certificateDER: certificate.certificateDER,
                    certificateRole: certificate.role
                ))
                continue
            }
            guard certificate.role == .authentication || certificate.role == .signature else {
                count(.ineligibleCertificateRole, in: &exclusions)
                continue
            }
            let identifier = certificate.reference.ckaID
            guard !duplicateCertificateIDs.contains(identifier),
                  !duplicateKeyIDs.contains(identifier) else {
                count(.duplicateIdentifier, in: &exclusions)
                continue
            }

            let matches = privateKeys.filter { $0.reference.ckaID == identifier }
            guard matches.count == 1, let key = matches.first else {
                count(.noUniqueKeyMatch, in: &exclusions)
                continue
            }
            guard certificate.publicKeyRepresentation == key.publicKeyRepresentation else {
                count(.publicKeyMismatch, in: &exclusions)
                continue
            }

            let algorithms = key.algorithms.intersection(allowedAlgorithms)
            identities.append(DNIeIdentityDescriptor(
                objectID: objectID(for: identifier, role: certificate.role),
                certificateDER: certificate.certificateDER,
                certificateRole: certificate.role,
                keyReference: key.reference,
                canSign: key.reference.usage.contains(.sign) && !algorithms.isEmpty,
                constraints: key.constraints,
                algorithms: algorithms
            ))
        }

        return TokenCatalogBuildResult(
            identities: identities,
            supportingCertificates: supportingCertificates,
            exclusionCounts: exclusions
        )
    }

    private func duplicateIDs(_ identifiers: [Data]) -> Set<Data> {
        let counts = identifiers.reduce(into: [Data: Int]()) { $0[$1, default: 0] += 1 }
        return Set(counts.compactMap { $0.value > 1 ? $0.key : nil })
    }

    private func count(
        _ exclusion: CatalogExclusion,
        in counts: inout [CatalogExclusion: Int]
    ) {
        counts[exclusion, default: 0] += 1
    }

    private func objectID(
        for identifier: Data,
        role: CertificateRole
    ) -> OpaqueObjectID {
        var input = Self.objectIDDomain
        input.append(instanceID)
        input.append(0)
        input.append(Data(roleDomain(role).utf8))
        input.append(0)
        input.append(identifier)
        return OpaqueObjectID(bytes: Data(SHA256.hash(data: input)))
    }

    private func roleDomain(_ role: CertificateRole) -> String {
        switch role {
        case .authentication: "authentication"
        case .signature: "signature"
        case .intermediate: "intermediate"
        case .component: "component"
        }
    }
}
