import Foundation
import XCTest
@testable import DNIeCore

final class AlgorithmTests: XCTestCase {
    func testOnlyExactSignObjectOperationAndAlgorithmIntersectionPasses() {
        let identity = makeIdentity(
            canSign: true,
            algorithms: [.rsaSignatureDigestPKCS1v15SHA256]
        )

        XCTAssertTrue(IdentityOperationPolicy.supports(
            identity: identity,
            objectID: identity.objectID,
            operation: .sign,
            algorithm: .rsaSignatureDigestPKCS1v15SHA256
        ))
        XCTAssertFalse(IdentityOperationPolicy.supports(
            identity: identity,
            objectID: OpaqueObjectID(bytes: Data(repeating: 0xBB, count: 32)),
            operation: .sign,
            algorithm: .rsaSignatureDigestPKCS1v15SHA256
        ))
        XCTAssertFalse(IdentityOperationPolicy.supports(
            identity: identity,
            objectID: identity.objectID,
            operation: .authenticate,
            algorithm: .rsaSignatureDigestPKCS1v15SHA256
        ))
        XCTAssertFalse(IdentityOperationPolicy.supports(
            identity: identity,
            objectID: identity.objectID,
            operation: .discover,
            algorithm: .rsaSignatureDigestPKCS1v15SHA256
        ))
    }

    func testMetadataAndProfileCapabilityMustBothPermitSigning() {
        let metadataDenied = makeIdentity(
            canSign: false,
            algorithms: [.rsaSignatureDigestPKCS1v15SHA256]
        )
        let profileDenied = makeIdentity(canSign: true, algorithms: [])

        for identity in [metadataDenied, profileDenied] {
            XCTAssertFalse(IdentityOperationPolicy.supports(
                identity: identity,
                objectID: identity.objectID,
                operation: .sign,
                algorithm: .rsaSignatureDigestPKCS1v15SHA256
            ))
        }
    }

    func testPlatformAlgorithmMappingRejectsEveryUnverifiedVariant() {
        XCTAssertEqual(
            KeyAlgorithm(exactPlatformName: "rsaSignatureDigestPKCS1v15SHA256"),
            .rsaSignatureDigestPKCS1v15SHA256
        )
        for unsupported in [
            "rsaSignatureMessagePKCS1v15SHA256",
            "rsaSignatureDigestPKCS1v15SHA384",
            "rsaSignatureDigestPSSSHA256",
            "rsaEncryptionPKCS1",
            "RSASignatureDigestPKCS1v15SHA256",
            "rsaSignatureDigestPKCS1v15SHA256 ",
            "",
        ] {
            XCTAssertNil(KeyAlgorithm(exactPlatformName: unsupported))
        }
    }

    private func makeIdentity(
        canSign: Bool,
        algorithms: Set<KeyAlgorithm>
    ) -> DNIeIdentityDescriptor {
        DNIeIdentityDescriptor(
            objectID: OpaqueObjectID(bytes: Data(repeating: 0xAA, count: 32)),
            certificateDER: Data([0x30, 0x00]),
            certificateRole: .authentication,
            keyReference: PKCS15ObjectReference(
                objectType: .privateKey,
                ckaID: Data([0x01]),
                label: nil,
                path: CardPath(components: [0x3F11, 0x0101]),
                usage: [.sign, .authenticate],
                keyReference: 1,
                authenticationReference: nil
            ),
            canSign: canSign,
            constraints: [.authenticate: Data([0x01])],
            algorithms: algorithms
        )
    }
}
