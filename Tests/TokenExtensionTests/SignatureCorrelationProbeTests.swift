#if SIGNATURE_CORRELATION_PROBE
import DNIeCore
import Foundation
import XCTest

final class SignatureCorrelationProbeTests: XCTestCase {
    private final class ConcurrentCounts: @unchecked Sendable {
        private let lock = NSLock()
        private var acceptedValue = 0
        private var rejectedValue = 0

        func recordAccepted() {
            lock.lock()
            acceptedValue += 1
            lock.unlock()
        }

        func recordRejected() {
            lock.lock()
            rejectedValue += 1
            lock.unlock()
        }

        var values: (accepted: Int, rejected: Int) {
            lock.lock()
            defer { lock.unlock() }
            return (acceptedValue, rejectedValue)
        }
    }

    func testAuthenticationNeededRequestBindsToSameInputReplay() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let probe = SignatureCorrelationProbe(generation: generation)
        let input = Data(repeating: 0x11, count: 32)

        let initial = try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: input
        )
        XCTAssertEqual(initial.flowOrdinal, 1)
        XCTAssertEqual(initial.equality, .first)
        try probe.markAuthenticationNeeded(initial)
        let auth = try probe.bindAuthentication(
            sessionID: sessionID,
            generation: generation
        )
        try probe.beginInitialVerify(auth)
        try probe.completeInitialVerify(auth, succeeded: true)

        let replay = try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: input
        )
        XCTAssertEqual(replay.flowOrdinal, 1)
        XCTAssertTrue(replay.isAuthenticationReplay)
        XCTAssertEqual(replay.equality, .authenticationReplay)
        try probe.beginSign(replay)
        probe.completeSign(replay, succeeded: true)

        XCTAssertEqual(probe.snapshot().flows.map(\.phase), [.completed])
        XCTAssertEqual(probe.snapshot().retainedInputCount, 1)
    }

    func testReplayRejectsChangedInputAndForeignSession() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let probe = SignatureCorrelationProbe(generation: generation)
        let initial = try reserveFirst(probe, generation: generation, sessionID: sessionID)
        try probe.markAuthenticationNeeded(initial)
        let auth = try probe.bindAuthentication(sessionID: sessionID, generation: generation)
        try probe.beginInitialVerify(auth)
        try probe.completeInitialVerify(auth, succeeded: true)

        XCTAssertThrowsError(try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x22, count: 32)
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .replayMismatch)
        }
        XCTAssertEqual(probe.snapshot().flows.map(\.phase), [.failed])
        XCTAssertTrue(probe.snapshot().scopeFailed)

        let foreignProbe = SignatureCorrelationProbe(generation: generation)
        let foreignInitial = try reserveFirst(
            foreignProbe,
            generation: generation,
            sessionID: sessionID
        )
        try foreignProbe.markAuthenticationNeeded(foreignInitial)
        let foreignAuth = try foreignProbe.bindAuthentication(
            sessionID: sessionID,
            generation: generation
        )
        try foreignProbe.beginInitialVerify(foreignAuth)
        try foreignProbe.completeInitialVerify(foreignAuth, succeeded: true)
        XCTAssertThrowsError(try foreignProbe.reserveSignRequest(
            sessionID: UUID(),
            generation: generation,
            input: Data(repeating: 0x11, count: 32)
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .replayMismatch)
        }
        XCTAssertTrue(foreignProbe.snapshot().scopeFailed)
    }

    func testCompletedDuplicateRejectsAndFreezesScope() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let probe = SignatureCorrelationProbe(generation: generation)
        try completeFirstFlow(probe, generation: generation, sessionID: sessionID)

        XCTAssertThrowsError(try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x11, count: 32)
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .replayMismatch)
        }
        XCTAssertTrue(probe.snapshot().scopeFailed)
        XCTAssertEqual(probe.snapshot().retainedInputCount, 0)
    }

    func testSecondDistinctAuthorizedFlowCompletesAndThirdFreezesScope() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let probe = SignatureCorrelationProbe(generation: generation)
        try completeFirstFlow(probe, generation: generation, sessionID: sessionID)

        let second = try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x22, count: 32)
        )
        XCTAssertEqual(second.equality, .distinctPrevious)
        try probe.markAuthorizedRequest(second)
        try probe.beginLeaseBackedVerify(second)
        try probe.completeLeaseBackedVerify(second, succeeded: true)
        try probe.beginSign(second)
        probe.completeSign(second, succeeded: true)
        XCTAssertEqual(probe.snapshot().retainedInputCount, 0)

        XCTAssertThrowsError(try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x33, count: 32)
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .budgetExhausted)
        }
        XCTAssertEqual(probe.snapshot().flows.count, 2)
        XCTAssertTrue(probe.snapshot().scopeFailed)
    }

    func testDistinctSecondFlowAndFailureStillConsumeBudget() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let probe = SignatureCorrelationProbe(generation: generation)
        try completeFirstFlow(probe, generation: generation, sessionID: sessionID)
        let second = try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x44, count: 32)
        )
        XCTAssertEqual(second.equality, .distinctPrevious)
        try probe.markAuthorizedRequest(second)
        probe.fail(second, reason: "lifecycle_failed")

        XCTAssertThrowsError(try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x55, count: 32)
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .scopeFailed)
        }
        XCTAssertEqual(probe.snapshot().flows.map(\.phase), [.completed, .failed])
        XCTAssertTrue(probe.snapshot().scopeFailed)
    }

    func testConcurrentReservationAllowsOnlyOneActiveFlow() {
        let generation = ConnectionGeneration()
        let probe = SignatureCorrelationProbe(generation: generation)
        let counts = ConcurrentCounts()

        DispatchQueue.concurrentPerform(iterations: 24) { ordinal in
            do {
                _ = try probe.reserveSignRequest(
                    sessionID: UUID(),
                    generation: generation,
                    input: Data(repeating: UInt8(ordinal), count: 32)
                )
                counts.recordAccepted()
            } catch {
                counts.recordRejected()
            }
        }

        XCTAssertEqual(counts.values.accepted, 1)
        XCTAssertEqual(counts.values.rejected, 23)
        XCTAssertEqual(probe.snapshot().flows.count, 1)
        XCTAssertTrue(probe.snapshot().scopeFailed)
    }

    func testScopeChangeAndAuthWithoutReservationFailClosed() throws {
        let generation = ConnectionGeneration()
        let staleProbe = SignatureCorrelationProbe(generation: generation)

        XCTAssertThrowsError(try staleProbe.reserveSignRequest(
            sessionID: UUID(),
            generation: ConnectionGeneration(),
            input: Data(repeating: 0x11, count: 32)
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .staleScope)
        }
        XCTAssertTrue(staleProbe.snapshot().scopeFailed)

        let missingProbe = SignatureCorrelationProbe(generation: generation)
        XCTAssertThrowsError(try missingProbe.bindAuthentication(
            sessionID: UUID(),
            generation: generation
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .missingAuthenticationRequest)
        }
        XCTAssertTrue(missingProbe.snapshot().scopeFailed)
    }

    func testInputExpiresWithoutRestoringBudgetAndTeardownIsIdempotent() async throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let probe = SignatureCorrelationProbe(
            generation: generation,
            retentionLifetime: .milliseconds(20)
        )
        try completeFirstFlow(probe, generation: generation, sessionID: sessionID)
        XCTAssertEqual(probe.snapshot().retainedInputCount, 1)
        try await Task<Never, Never>.sleep(for: .milliseconds(80))
        XCTAssertEqual(probe.snapshot().retainedInputCount, 0)
        XCTAssertEqual(probe.snapshot().flows.count, 1)
        XCTAssertTrue(probe.snapshot().scopeFailed)

        XCTAssertThrowsError(try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x11, count: 32)
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .scopeFailed)
        }
        probe.teardown()
        probe.teardown()
        let snapshot = probe.snapshot()
        XCTAssertTrue(snapshot.tornDown)
        XCTAssertEqual(snapshot.retainedInputCount, 0)
        XCTAssertEqual(snapshot.flows.count, 1)
        XCTAssertThrowsError(try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x11, count: 32)
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .tornDown)
        }
    }

    func testPendingInputExpiryPreventsVerifyAndAnyFurtherFlow() async throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let probe = SignatureCorrelationProbe(
            generation: generation,
            retentionLifetime: .milliseconds(20)
        )
        let initial = try reserveFirst(probe, generation: generation, sessionID: sessionID)
        try probe.markAuthenticationNeeded(initial)
        let auth = try probe.bindAuthentication(sessionID: sessionID, generation: generation)
        try await Task<Never, Never>.sleep(for: .milliseconds(80))

        XCTAssertThrowsError(try probe.beginInitialVerify(auth)) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .scopeFailed)
        }
        XCTAssertEqual(probe.snapshot().flows.map(\.phase), [.failed])
        XCTAssertEqual(probe.snapshot().retainedInputCount, 0)
    }

    func testFailedFlowCannotAdmitAnotherFlowOrAuthentication() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let probe = SignatureCorrelationProbe(generation: generation)
        let first = try reserveFirst(probe, generation: generation, sessionID: sessionID)
        probe.fail(first, reason: "synthetic_failure")

        XCTAssertThrowsError(try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x22, count: 32)
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .scopeFailed)
        }
        XCTAssertThrowsError(try probe.bindAuthentication(
            sessionID: sessionID,
            generation: generation
        )) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .scopeFailed)
        }
    }

    func testFlowCannotRunBothInitialAndLeaseBackedVerify() throws {
        let generation = ConnectionGeneration()
        let sessionID = UUID()
        let probe = SignatureCorrelationProbe(generation: generation)
        let initial = try reserveFirst(probe, generation: generation, sessionID: sessionID)
        try probe.markAuthenticationNeeded(initial)
        let auth = try probe.bindAuthentication(sessionID: sessionID, generation: generation)
        try probe.beginInitialVerify(auth)
        try probe.completeInitialVerify(auth, succeeded: true)
        let replay = try reserveFirst(probe, generation: generation, sessionID: sessionID)

        XCTAssertThrowsError(try probe.beginLeaseBackedVerify(replay)) {
            XCTAssertEqual($0 as? SignatureCorrelationProbeError, .invalidTransition)
        }
        XCTAssertTrue(probe.snapshot().scopeFailed)
    }

    func testSourceHooksFenceSensitiveWorkAndRemainCompileFlagged() throws {
        let source = try String(
            contentsOf: repositoryRoot().appendingPathComponent(
                "TokenExtension/TokenSession.swift"
            ),
            encoding: .utf8
        )
        XCTAssertTrue(source.contains("#if SIGNATURE_CORRELATION_PROBE"))
        let reservation = try XCTUnwrap(source.range(of: "reserveSignRequest("))
        let signCard = try XCTUnwrap(source.range(
            of: "SendableSmartCardHandle(try getSmartCard())",
            range: reservation.upperBound..<source.endIndex
        ))
        XCTAssertLessThan(reservation.lowerBound, signCard.lowerBound)
        let authBinding = try XCTUnwrap(source.range(of: "bindAuthentication("))
        let credentialLoad = try XCTUnwrap(source.range(
            of: "CredentialAssetStore.loadBundledGeneration2()",
            range: authBinding.upperBound..<source.endIndex
        ))
        XCTAssertLessThan(authBinding.lowerBound, credentialLoad.lowerBound)
        let leaseVerify = try XCTUnwrap(source.range(of: "beginLeaseBackedVerify("))
        let refreshCredentialLoad = try XCTUnwrap(source.range(
            of: "CredentialAssetStore.loadBundledGeneration2()",
            range: leaseVerify.upperBound..<source.endIndex
        ))
        XCTAssertLessThan(leaseVerify.lowerBound, refreshCredentialLoad.lowerBound)
    }

    private func reserveFirst(
        _ probe: SignatureCorrelationProbe,
        generation: ConnectionGeneration,
        sessionID: UUID
    ) throws -> SignatureCorrelationSignTicket {
        try probe.reserveSignRequest(
            sessionID: sessionID,
            generation: generation,
            input: Data(repeating: 0x11, count: 32)
        )
    }

    private func completeFirstFlow(
        _ probe: SignatureCorrelationProbe,
        generation: ConnectionGeneration,
        sessionID: UUID
    ) throws {
        let initial = try reserveFirst(probe, generation: generation, sessionID: sessionID)
        try probe.markAuthenticationNeeded(initial)
        let auth = try probe.bindAuthentication(sessionID: sessionID, generation: generation)
        try probe.beginInitialVerify(auth)
        try probe.completeInitialVerify(auth, succeeded: true)
        let replay = try reserveFirst(probe, generation: generation, sessionID: sessionID)
        try probe.beginSign(replay)
        probe.completeSign(replay, succeeded: true)
    }

    private func repositoryRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
#endif
