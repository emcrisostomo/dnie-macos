import DNIeCore
import Foundation

/// Test-only alternate profile. All identifiers and paths are synthetic.
struct FakeCardProfile: PublicCatalogCardProfile {
    let descriptor: CardProfileDescriptor
    private let certificateDER: Data
    private let publicKeyRepresentation: Data

    init(certificateDER: Data, publicKeyRepresentation: Data) {
        self.certificateDER = certificateDER
        self.publicKeyRepresentation = publicKeyRepresentation
        descriptor = CardProfileDescriptor(
            profileID: "org.dniemacos.tests.synthetic-public",
            version: ProfileVersion("1"),
            applicationSelector: Data("synthetic-public-profile".utf8),
            capabilityGate: CapabilityGate(requirements: [
                .recognize: [EvidenceRequirement(
                    evidenceID: "TEST-SYNTHETIC-PROFILE",
                    state: .experimentallyVerified
                )],
                .instance: [EvidenceRequirement(
                    evidenceID: "TEST-SYNTHETIC-INSTANCE",
                    state: .experimentallyVerified
                )],
                .discover: [EvidenceRequirement(
                    evidenceID: "TEST-SYNTHETIC-CATALOG",
                    state: .experimentallyVerified
                )],
            ]),
            limits: ProfileLimits(
                maximumCommandLength: 256,
                maximumResponseLength: 256,
                maximumDirectoryLength: 256,
                maximumCertificateLength: 32 * 1_024
            )
        )
    }

    func makePublicCatalog(instanceID: Data) -> TokenCatalogBuildResult {
        guard isEnabled(.instance), isEnabled(.discover) else {
            return TokenCatalogBuildResult(
                identities: [], supportingCertificates: [], exclusionCounts: [:]
            )
        }
        let identifier = Data("synthetic-key-reference".utf8)
        let certificate = CatalogCertificateCandidate(
            reference: PKCS15ObjectReference(
                objectType: .certificate,
                ckaID: identifier,
                label: nil,
                path: CardPath(components: [0x3F00, 0x1001]),
                usage: [],
                keyReference: nil,
                authenticationReference: nil
            ),
            certificateDER: certificateDER,
            role: .authentication,
            publicKeyRepresentation: publicKeyRepresentation
        )
        let key = CatalogPrivateKeyCandidate(
            reference: PKCS15ObjectReference(
                objectType: .privateKey,
                ckaID: identifier,
                label: nil,
                path: CardPath(components: [0x3F00, 0x1002]),
                usage: [],
                keyReference: 0x02,
                authenticationReference: nil
            ),
            publicKeyRepresentation: publicKeyRepresentation,
            constraints: [:],
            algorithms: []
        )
        return TokenCatalogBuilder(instanceID: instanceID, allowedAlgorithms: [])
            .build(certificates: [certificate], privateKeys: [key])
    }
}
