import CryptoTokenKit
import DNIeCore
import Foundation
import XCTest

final class TokenSessionTests: XCTestCase {
    func testSupportRequiresExactOperationObjectAndAlgorithm() {
        let identity = makeIdentity()
        let keyObjectID = Data(repeating: 0xB1, count: 32)
        let identities = [keyObjectID: identity]

        XCTAssertTrue(TokenSessionPolicy.supports(
            operation: .signData,
            keyObjectID: keyObjectID,
            algorithm: .rsaSignatureDigestPKCS1v15SHA256,
            identitiesByKeyObjectID: identities
        ))
        XCTAssertFalse(TokenSessionPolicy.supports(
            operation: .decryptData,
            keyObjectID: keyObjectID,
            algorithm: .rsaSignatureDigestPKCS1v15SHA256,
            identitiesByKeyObjectID: identities
        ))
        XCTAssertFalse(TokenSessionPolicy.supports(
            operation: .signData,
            keyObjectID: Data(repeating: 0xB2, count: 32),
            algorithm: .rsaSignatureDigestPKCS1v15SHA256,
            identitiesByKeyObjectID: identities
        ))
        XCTAssertFalse(TokenSessionPolicy.supports(
            operation: .signData,
            keyObjectID: keyObjectID,
            algorithm: nil,
            identitiesByKeyObjectID: identities
        ))
    }

    func testConstraintMustBeExactAndBelongToAnEnabledIdentity() {
        let identity = makeIdentity()
        let identities = [Data(repeating: 0xB1, count: 32): identity]
        let exact = Data("org.dniemacos.authentication.constraint.v1".utf8)

        XCTAssertEqual(
            TokenSessionPolicy.identity(
                operation: .signData,
                constraint: exact,
                identitiesByKeyObjectID: identities
            ),
            identity
        )
        XCTAssertNil(TokenSessionPolicy.identity(
            operation: .signData,
            constraint: Data("foreign".utf8),
            identitiesByKeyObjectID: identities
        ))
        XCTAssertNil(TokenSessionPolicy.identity(
            operation: .decryptData,
            constraint: exact,
            identitiesByKeyObjectID: identities
        ))
    }

    func testAuthorizationContextRequiresExactSessionAndGeneration() {
        let sessionID = UUID()
        let generation = ConnectionGeneration()

        XCTAssertTrue(TokenSessionPolicy.contextMatches(
            expectedSessionID: sessionID,
            expectedGeneration: generation,
            actualSessionID: sessionID,
            actualGeneration: generation
        ))
        XCTAssertFalse(TokenSessionPolicy.contextMatches(
            expectedSessionID: sessionID,
            expectedGeneration: generation,
            actualSessionID: UUID(),
            actualGeneration: generation
        ))
        XCTAssertFalse(TokenSessionPolicy.contextMatches(
            expectedSessionID: sessionID,
            expectedGeneration: generation,
            actualSessionID: sessionID,
            actualGeneration: ConnectionGeneration()
        ))
    }

    func testDelegateSourceHasNoFallbackSessionMutationOrLogging() throws {
        let source = try String(
            contentsOf: repositoryRoot().appendingPathComponent(
                "TokenExtension/TokenSession.swift"
            ),
            encoding: .utf8
        )

        XCTAssertTrue(source.contains("algorithm.supportsAlgorithm("))
        XCTAssertTrue(source.contains("algorithm.isAlgorithm("))
        XCTAssertTrue(source.contains("category: \"private-operation\""))
        XCTAssertTrue(source.contains("CredentialAssetStore.loadBundledGeneration2()"))
        XCTAssertTrue(source.contains("DNIeSigning.signSHA256Digest("))
        for forbidden in [
            "beginSession", "endSession", "SecKeyCreateSignature",
            "os_log", "print(", "password.count", "dataToSign, privacy",
            "keyObjectID, privacy", "constraint, privacy", "password, privacy",
        ] {
            XCTAssertFalse(source.contains(forbidden), forbidden)
        }
    }

    func testRecoveryAndLateCallbackGatesPrecedePasswordAndCardWork() throws {
        let source = try String(
            contentsOf: repositoryRoot().appendingPathComponent(
                "TokenExtension/TokenSession.swift"
            ),
            encoding: .utf8
        )
        let recovery = try XCTUnwrap(source.range(
            of: "DNIePlainStateRecovery.execute("
        ))
        let passwordOperation = try XCTUnwrap(source.range(
            of: "operation.auth.password_operation_created"
        ))
        let callbackGate = try XCTUnwrap(source.range(
            of: "lifecycle.beginAuthorizationConsumption(lifecycleClaim)"
        ))
        let sensitiveCard = try XCTUnwrap(source.range(
            of: "cardHandle.card.isSensitive = true"
        ))
        let channelEstablishment = try XCTUnwrap(source.range(
            of: "establisher.establishPINChannel()"
        ))

        XCTAssertLessThan(recovery.lowerBound, passwordOperation.lowerBound)
        XCTAssertLessThan(callbackGate.lowerBound, channelEstablishment.lowerBound)
        XCTAssertLessThan(sensitiveCard.lowerBound, channelEstablishment.lowerBound)
        XCTAssertTrue(source.contains("defaultTimeoutNanoseconds"))
        XCTAssertTrue(source.contains("task.cancel()"))
        XCTAssertFalse(source.contains("card.transmit("))
        XCTAssertFalse(source.contains("beginSession"))
        XCTAssertFalse(source.contains("endSession"))
    }

    func testSuccessfulSignRetainsOnlyBoundAuthorizationContext() throws {
        let source = try String(
            contentsOf: repositoryRoot().appendingPathComponent(
                "TokenExtension/TokenSession.swift"
            ),
            encoding: .utf8
        )
        let successStart = try XCTUnwrap(source.range(
            of: "try lifecycle.completeSign(signLease, succeeded: true)"
        ))
        let successEnd = try XCTUnwrap(source.range(
            of: "return signature",
            range: successStart.upperBound..<source.endIndex
        ))
        let successPath = source[successStart.lowerBound..<successEnd.upperBound]

        XCTAssertTrue(successPath.contains(
            "operation.sign.authorization_retained=true"
        ))
        XCTAssertFalse(successPath.contains("state.clear()"))
        XCTAssertFalse(successPath.contains("controller.invalidate"))
        XCTAssertFalse(successPath.contains("recovery_required"))
    }

    func testSignFailureDiagnosticsRemainCategorical() {
        XCTAssertEqual(
            TokenSessionSignFailureCategory.classify(
                SecureChannelTransportError.invalidAuthentication
            ),
            .channelAuthentication
        )
        XCTAssertEqual(
            TokenSessionSignFailureCategory.classify(
                SecureChannelTransportError.outerStatus(
                    CardStatus(first: 0x69, second: 0x88)
                )
            ),
            .channelOuterStatus
        )
        XCTAssertEqual(
            TokenSessionSignFailureCategory.classify(
                PlainStateRecoveryError.invalidPlainResponse
            ),
            .plainState
        )
        XCTAssertEqual(
            TokenSessionSignFailureCategory.classify(
                DNIeSigningError.invalidCardResponse
            ),
            .profile
        )
    }

    func testSubsequentSignPerformsOneBoundedLeaseReauthorization() throws {
        let source = try String(
            contentsOf: repositoryRoot().appendingPathComponent(
                "TokenExtension/TokenSession.swift"
            ),
            encoding: .utf8
        )
        let refreshStart = try XCTUnwrap(source.range(
            of: "if signLease.preparation == .refreshUserChannel"
        ))
        let refreshEnd = try XCTUnwrap(source.range(
            of: "let signingContext = operationContext",
            range: refreshStart.upperBound..<source.endIndex
        ))
        let refreshPath = source[
            refreshStart.lowerBound..<refreshEnd.upperBound
        ]

        XCTAssertTrue(refreshPath.contains("DNIePlainStateRecovery.synchronize("))
        XCTAssertTrue(refreshPath.contains("pinLease.withCredential("))
        XCTAssertTrue(refreshPath.contains("establisher.establishPINChannel()"))
        XCTAssertTrue(refreshPath.contains("pinChannel.verify("))
        XCTAssertTrue(refreshPath.contains("establisher.establishUserChannel("))
        XCTAssertTrue(refreshPath.contains("from: pinChannel"))
        XCTAssertEqual(refreshPath.components(separatedBy: "pinChannel.verify(").count, 2)
        XCTAssertFalse(refreshPath.contains("DNIePINAuthOperation("))
        XCTAssertFalse(refreshPath.contains("password_operation_created"))
    }

    func testBlockingAsyncHasTerminalCancellationBound() {
        XCTAssertThrowsError(try BlockingAsync.run(
            timeoutNanoseconds: 1_000_000
        ) {
            try await Task<Never, Never>.sleep(for: .seconds(1))
            return true
        }) { error in
            let error = error as NSError
            XCTAssertEqual(error.domain, TKErrorDomain)
            XCTAssertEqual(error.code, TKError.Code.communicationError.rawValue)
        }
    }

    private func makeIdentity() -> DNIeIdentityDescriptor {
        DNIeIdentityDescriptor(
            objectID: OpaqueObjectID(bytes: Data(repeating: 0xA1, count: 32)),
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
            canSign: true,
            constraints: [
                .sign: Data("org.dniemacos.authentication.constraint.v1".utf8),
            ],
            algorithms: [.rsaSignatureDigestPKCS1v15SHA256]
        )
    }

    private func repositoryRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
