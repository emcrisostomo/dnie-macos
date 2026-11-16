import DNIeCore
import Foundation
import XCTest

final class LifecycleTests: XCTestCase {
    private func assertAuthorizationClaimRejected(
        _ expected: AuthorizationClaimBlocker,
        _ operation: () throws -> Void,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try operation(), file: file, line: line) {
            XCTAssertEqual(
                $0 as? TokenSessionLifecycleError,
                .authorizationClaimRejected(expected),
                file: file,
                line: line
            )
        }
    }

    func testLateAuthorizationCallbackIsRejectedAfterInvalidation() throws {
        let generation = ConnectionGeneration()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let claim = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )

        coordinator.invalidate(generation: generation)

        XCTAssertThrowsError(try coordinator.completeAuthorization(claim)) {
            XCTAssertEqual($0 as? TokenSessionLifecycleError, .invalidState)
        }
        XCTAssertThrowsError(try coordinator.validateAuthorization(claim)) {
            XCTAssertEqual($0 as? TokenSessionLifecycleError, .invalidState)
        }
        XCTAssertEqual(coordinator.snapshot(), .invalid)
    }

    func testExtensionRestartCannotReceiveOldCoordinatorCallback() throws {
        let oldGeneration = ConnectionGeneration()
        let oldCoordinator = TokenSessionLifecycleCoordinator(
            generation: oldGeneration
        )
        let oldClaim = try oldCoordinator.claimAuthorization(
            sessionID: UUID(),
            generation: oldGeneration
        )
        oldCoordinator.invalidate(generation: oldGeneration)

        let newGeneration = ConnectionGeneration()
        let newCoordinator = TokenSessionLifecycleCoordinator(
            generation: newGeneration
        )
        let newClaim = try newCoordinator.claimAuthorization(
            sessionID: UUID(),
            generation: newGeneration
        )

        XCTAssertThrowsError(try oldCoordinator.completeAuthorization(oldClaim))
        XCTAssertEqual(newCoordinator.snapshot(), .authPending(.initial))
        try newCoordinator.cancelAuthorization(newClaim)
        XCTAssertEqual(newCoordinator.snapshot(), .publicReady)
    }

    func testBrowserRestartClaimsRecoveryBeforeNewAuthorization() throws {
        let generation = ConnectionGeneration()
        let firstSession = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let firstAuthorization = try coordinator.claimAuthorization(
            sessionID: firstSession,
            generation: generation
        )
        try coordinator.completeAuthorization(firstAuthorization)
        let sign = try coordinator.beginSign(
            sessionID: firstSession,
            generation: generation
        )
        try coordinator.completeSign(sign, succeeded: true)
        coordinator.cancelSession(
            sessionID: firstSession,
            generation: generation
        )

        let restartClaim = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )

        XCTAssertEqual(restartClaim.preparation, .recoverBeforeAuthorization)
        XCTAssertEqual(
            coordinator.snapshot(),
            .authPending(.recoverBeforeAuthorization)
        )

        XCTAssertThrowsError(
            try coordinator.completeAuthorization(restartClaim)
        ) {
            XCTAssertEqual($0 as? TokenSessionLifecycleError, .invalidState)
        }
        try coordinator.completeRecovery(restartClaim)
        try coordinator.completeAuthorization(restartClaim)
        XCTAssertEqual(coordinator.snapshot(), .authorized)
    }

    func testSuccessfulSignsRetainAuthorizationForOwningSession() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let claim = try coordinator.claimAuthorization(
            sessionID: sessionID,
            generation: generation
        )
        try coordinator.completeAuthorization(claim)

        let firstSign = try coordinator.beginSign(
            sessionID: sessionID,
            generation: generation
        )
        XCTAssertEqual(firstSign.preparation, .useEstablishedChannel)
        try coordinator.completeSign(firstSign, succeeded: true)
        XCTAssertEqual(coordinator.snapshot(), .authorized)

        let secondSign = try coordinator.beginSign(
            sessionID: sessionID,
            generation: generation
        )
        XCTAssertEqual(secondSign.preparation, .refreshUserChannel)
        try coordinator.completeSign(secondSign, succeeded: true)
        XCTAssertEqual(coordinator.snapshot(), .authorized)
    }

    func testForeignClaimRetiresIdleAuthorizedOwnerAfterSuccessfulSign() throws {
        let generation = ConnectionGeneration()
        let oldSession = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let oldClaim = try coordinator.claimAuthorization(
            sessionID: oldSession,
            generation: generation
        )
        try coordinator.completeAuthorization(oldClaim)
        let oldSign = try coordinator.beginSign(
            sessionID: oldSession,
            generation: generation
        )
        try coordinator.completeSign(oldSign, succeeded: true)

        let replacement = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )

        XCTAssertEqual(replacement.preparation, .recoverBeforeAuthorization)
        XCTAssertEqual(
            coordinator.snapshot(),
            .authPending(.recoverBeforeAuthorization)
        )
        XCTAssertThrowsError(
            try coordinator.beginSign(
                sessionID: oldSession,
                generation: generation
            )
        ) {
            XCTAssertEqual($0 as? TokenSessionLifecycleError, .operationInFlight)
        }
        XCTAssertThrowsError(try coordinator.completeSign(oldSign, succeeded: true)) {
            XCTAssertEqual($0 as? TokenSessionLifecycleError, .staleCallback)
        }
        XCTAssertThrowsError(try coordinator.requireReauthorization(oldSign)) {
            XCTAssertEqual($0 as? TokenSessionLifecycleError, .staleCallback)
        }
    }

    func testLateOldCancellationCannotAffectRecoveredForeignOwner() throws {
        let generation = ConnectionGeneration()
        let oldSession = UUID()
        let newSession = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let oldClaim = try coordinator.claimAuthorization(
            sessionID: oldSession,
            generation: generation
        )
        try coordinator.completeAuthorization(oldClaim)
        let oldSign = try coordinator.beginSign(
            sessionID: oldSession,
            generation: generation
        )
        try coordinator.completeSign(oldSign, succeeded: true)

        let replacement = try coordinator.claimAuthorization(
            sessionID: newSession,
            generation: generation
        )
        try coordinator.completeRecovery(replacement)
        try coordinator.markAuthorizationAwaitingInput(replacement)
        try coordinator.beginAuthorizationConsumption(replacement)
        try coordinator.completeAuthorization(replacement)

        coordinator.cancelSession(
            sessionID: oldSession,
            generation: generation
        )

        XCTAssertEqual(coordinator.snapshot(), .authorized)
        _ = try coordinator.beginSign(
            sessionID: newSession,
            generation: generation
        )
    }

    func testCancelledForeignReplacementBeforeRecoveryDoesNotRestoreOldOwner() throws {
        let generation = ConnectionGeneration()
        let oldSession = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let oldClaim = try coordinator.claimAuthorization(
            sessionID: oldSession,
            generation: generation
        )
        try coordinator.completeAuthorization(oldClaim)
        let oldSign = try coordinator.beginSign(
            sessionID: oldSession,
            generation: generation
        )
        try coordinator.completeSign(oldSign, succeeded: true)
        let replacement = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )

        try coordinator.cancelAuthorization(replacement)

        XCTAssertEqual(coordinator.snapshot(), .recoveryRequired)
        XCTAssertThrowsError(
            try coordinator.beginSign(
                sessionID: oldSession,
                generation: generation
            )
        ) {
            XCTAssertEqual($0 as? TokenSessionLifecycleError, .invalidState)
        }
        let retry = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )
        XCTAssertEqual(retry.preparation, .recoverBeforeAuthorization)
    }

    func testCancelledForeignReplacementAfterRecoveryDoesNotRestoreOldOwner() throws {
        let generation = ConnectionGeneration()
        let oldSession = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let oldClaim = try coordinator.claimAuthorization(
            sessionID: oldSession,
            generation: generation
        )
        try coordinator.completeAuthorization(oldClaim)
        let oldSign = try coordinator.beginSign(
            sessionID: oldSession,
            generation: generation
        )
        try coordinator.completeSign(oldSign, succeeded: true)
        let replacement = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )
        try coordinator.completeRecovery(replacement)

        try coordinator.cancelAuthorization(replacement)

        XCTAssertEqual(coordinator.snapshot(), .publicReady)
        XCTAssertThrowsError(
            try coordinator.beginSign(
                sessionID: oldSession,
                generation: generation
            )
        ) {
            XCTAssertEqual($0 as? TokenSessionLifecycleError, .invalidState)
        }
        let fresh = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )
        XCTAssertEqual(fresh.preparation, .initial)
    }

    func testNewAuthorizationStartsWithItsFreshlyEstablishedUserChannel() throws {
        let generation = ConnectionGeneration()
        let firstSession = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let firstClaim = try coordinator.claimAuthorization(
            sessionID: firstSession,
            generation: generation
        )
        try coordinator.completeAuthorization(firstClaim)
        let firstSign = try coordinator.beginSign(
            sessionID: firstSession,
            generation: generation
        )
        try coordinator.completeSign(firstSign, succeeded: true)
        coordinator.cancelSession(
            sessionID: firstSession,
            generation: generation
        )

        let secondSession = UUID()
        let secondClaim = try coordinator.claimAuthorization(
            sessionID: secondSession,
            generation: generation
        )
        try coordinator.completeRecovery(secondClaim)
        try coordinator.completeAuthorization(secondClaim)
        let secondSessionFirstSign = try coordinator.beginSign(
            sessionID: secondSession,
            generation: generation
        )

        XCTAssertEqual(
            secondSessionFirstSign.preparation,
            .useEstablishedChannel
        )
    }

    func testSessionEndAfterRetainedAuthorizationRequiresRecovery() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let claim = try coordinator.claimAuthorization(
            sessionID: sessionID,
            generation: generation
        )
        try coordinator.completeAuthorization(claim)
        let sign = try coordinator.beginSign(
            sessionID: sessionID,
            generation: generation
        )
        try coordinator.completeSign(sign, succeeded: true)

        coordinator.cancelSession(
            sessionID: sessionID,
            generation: generation
        )

        XCTAssertEqual(coordinator.snapshot(), .recoveryRequired)
        let nextClaim = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )
        XCTAssertEqual(nextClaim.preparation, .recoverBeforeAuthorization)
    }

    func testFailedSignInvalidatesRetainedAuthorization() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let claim = try coordinator.claimAuthorization(
            sessionID: sessionID,
            generation: generation
        )
        try coordinator.completeAuthorization(claim)
        let sign = try coordinator.beginSign(
            sessionID: sessionID,
            generation: generation
        )

        try coordinator.completeSign(sign, succeeded: false)

        XCTAssertEqual(coordinator.snapshot(), .invalid)
        XCTAssertThrowsError(try coordinator.beginSign(
            sessionID: sessionID,
            generation: generation
        ))
    }

    func testExpiredCredentialLeaseReturnsLifecycleToRecoverableAuthentication() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let claim = try coordinator.claimAuthorization(
            sessionID: sessionID,
            generation: generation
        )
        try coordinator.completeAuthorization(claim)
        let firstSign = try coordinator.beginSign(
            sessionID: sessionID,
            generation: generation
        )
        try coordinator.completeSign(firstSign, succeeded: true)
        let secondSign = try coordinator.beginSign(
            sessionID: sessionID,
            generation: generation
        )

        try coordinator.requireReauthorization(secondSign)

        XCTAssertEqual(coordinator.snapshot(), .recoveryRequired)
        let replacement = try coordinator.claimAuthorization(
            sessionID: sessionID,
            generation: generation
        )
        XCTAssertEqual(replacement.preparation, .recoverBeforeAuthorization)
    }

    func testConcurrentAuthorizationRequestsCreateOneClaim() throws {
        let generation = ConnectionGeneration()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        _ = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )

        assertAuthorizationClaimRejected(.authorizationPreparing) {
            _ = try coordinator.claimAuthorization(
                sessionID: UUID(),
                generation: generation
            )
        }
        XCTAssertEqual(coordinator.snapshot(), .authPending(.initial))
    }

    func testAbandonedPasswordClaimCanBeReplacedWithoutRevivingItsCallback() throws {
        let generation = ConnectionGeneration()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let clock = ContinuousClock()
        let start = clock.now
        let abandoned = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation,
            now: start
        )
        try coordinator.markAuthorizationAwaitingInput(
            abandoned,
            now: start
        )

        assertAuthorizationClaimRejected(.authorizationAwaitingInput) {
            _ = try coordinator.claimAuthorization(
                sessionID: UUID(),
                generation: generation,
                now: start.advanced(by: .seconds(299))
            )
        }

        let replacement = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation,
            now: start.advanced(by: .seconds(301))
        )
        XCTAssertEqual(
            replacement.preparation,
            .replaceAbandonedAuthorization
        )
        try coordinator.markAuthorizationAwaitingInput(
            replacement,
            now: start.advanced(by: .seconds(301))
        )
        XCTAssertThrowsError(
            try coordinator.beginAuthorizationConsumption(abandoned)
        ) {
            XCTAssertEqual(
                $0 as? TokenSessionLifecycleError,
                .staleCallback
            )
        }
        coordinator.invalidateAuthorization(abandoned)
        XCTAssertEqual(
            coordinator.snapshot(),
            .authPending(.replaceAbandonedAuthorization)
        )

        try coordinator.beginAuthorizationConsumption(replacement)
        try coordinator.completeAuthorization(replacement)
        XCTAssertEqual(coordinator.snapshot(), .authorized)
        coordinator.invalidateAuthorization(abandoned)
        XCTAssertEqual(coordinator.snapshot(), .authorized)
    }

    func testPreparingAuthorizationNeverExpires() throws {
        let generation = ConnectionGeneration()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let clock = ContinuousClock()
        let start = clock.now
        _ = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation,
            now: start
        )

        assertAuthorizationClaimRejected(.authorizationPreparing) {
            _ = try coordinator.claimAuthorization(
                sessionID: UUID(),
                generation: generation,
                now: start.advanced(by: .seconds(3_600))
            )
        }
    }

    func testConsumingAuthorizationNeverExpires() throws {
        let generation = ConnectionGeneration()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let clock = ContinuousClock()
        let start = clock.now
        let claim = try coordinator.claimAuthorization(
            sessionID: UUID(),
            generation: generation,
            now: start
        )
        try coordinator.markAuthorizationAwaitingInput(claim, now: start)
        try coordinator.beginAuthorizationConsumption(claim)

        assertAuthorizationClaimRejected(.authorizationConsuming) {
            _ = try coordinator.claimAuthorization(
                sessionID: UUID(),
                generation: generation,
                now: start.advanced(by: .seconds(3_600))
            )
        }
    }

    func testAuthorizationClaimBlockersAreCategoricalAndPrivacySafe() throws {
        let staleCoordinator = TokenSessionLifecycleCoordinator(
            generation: ConnectionGeneration()
        )
        assertAuthorizationClaimRejected(.staleGeneration) {
            _ = try staleCoordinator.claimAuthorization(
                sessionID: UUID(),
                generation: ConnectionGeneration()
            )
        }

        let invalidGeneration = ConnectionGeneration()
        let invalidCoordinator = TokenSessionLifecycleCoordinator(
            generation: invalidGeneration
        )
        invalidCoordinator.invalidate(generation: invalidGeneration)
        assertAuthorizationClaimRejected(.invalid) {
            _ = try invalidCoordinator.claimAuthorization(
                sessionID: UUID(),
                generation: invalidGeneration
            )
        }

        let authorizedGeneration = ConnectionGeneration()
        let authorizedCoordinator = TokenSessionLifecycleCoordinator(
            generation: authorizedGeneration
        )
        let authorizedSession = UUID()
        let authorizedClaim = try authorizedCoordinator.claimAuthorization(
            sessionID: authorizedSession,
            generation: authorizedGeneration
        )
        try authorizedCoordinator.completeAuthorization(authorizedClaim)
        assertAuthorizationClaimRejected(.authorizedSession) {
            _ = try authorizedCoordinator.claimAuthorization(
                sessionID: authorizedSession,
                generation: authorizedGeneration
            )
        }
        assertAuthorizationClaimRejected(.authorizedSession) {
            _ = try authorizedCoordinator.claimAuthorization(
                sessionID: UUID(),
                generation: authorizedGeneration
            )
        }

        let signingGeneration = ConnectionGeneration()
        let signingCoordinator = TokenSessionLifecycleCoordinator(
            generation: signingGeneration
        )
        let signingSession = UUID()
        let signingClaim = try signingCoordinator.claimAuthorization(
            sessionID: signingSession,
            generation: signingGeneration
        )
        try signingCoordinator.completeAuthorization(signingClaim)
        _ = try signingCoordinator.beginSign(
            sessionID: signingSession,
            generation: signingGeneration
        )
        assertAuthorizationClaimRejected(.activeSign) {
            _ = try signingCoordinator.claimAuthorization(
                sessionID: UUID(),
                generation: signingGeneration
            )
        }
    }

    func testLateSignCompletionCannotReviveInvalidState() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let claim = try coordinator.claimAuthorization(
            sessionID: sessionID,
            generation: generation
        )
        try coordinator.completeAuthorization(claim)
        let sign = try coordinator.beginSign(
            sessionID: sessionID,
            generation: generation
        )

        coordinator.invalidate(generation: generation)

        XCTAssertThrowsError(try coordinator.completeSign(sign, succeeded: true))
        XCTAssertEqual(coordinator.snapshot(), .invalid)
    }

    func testCancelledSessionRejectsLatePasswordCallbackBeforeCardWork() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let coordinator = TokenSessionLifecycleCoordinator(generation: generation)
        let claim = try coordinator.claimAuthorization(
            sessionID: sessionID,
            generation: generation
        )

        coordinator.cancelSession(
            sessionID: sessionID,
            generation: generation
        )

        XCTAssertThrowsError(try coordinator.validateAuthorization(claim)) {
            XCTAssertEqual($0 as? TokenSessionLifecycleError, .staleCallback)
        }
        XCTAssertEqual(coordinator.snapshot(), .publicReady)
    }
}
