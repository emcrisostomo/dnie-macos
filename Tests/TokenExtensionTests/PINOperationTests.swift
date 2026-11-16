import DNIeCore
import Foundation
import XCTest

final class PINOperationTests: XCTestCase {
    func testOnlyDocumentedPINStatusesReceivePINMeanings() {
        XCTAssertEqual(
            DNIeStatusMapper.pinVerification(CardStatus(first: 0x90, second: 0x00)),
            .accepted
        )
        XCTAssertEqual(
            DNIeStatusMapper.pinVerification(CardStatus(first: 0x63, second: 0xC3)),
            .incorrect(remainingAttempts: 3)
        )
        XCTAssertEqual(
            DNIeStatusMapper.pinVerification(CardStatus(first: 0x63, second: 0xC0)),
            .incorrect(remainingAttempts: 0)
        )
        XCTAssertEqual(
            DNIeStatusMapper.pinVerification(CardStatus(first: 0x69, second: 0x83)),
            .blocked
        )
        for status in [
            CardStatus(first: 0x63, second: 0xB3),
            CardStatus(first: 0x69, second: 0x82),
            CardStatus(first: 0x69, second: 0x87),
            CardStatus(first: 0x6F, second: 0x00),
        ] {
            XCTAssertEqual(DNIeStatusMapper.pinVerification(status), .unknown(status))
        }
    }

    func testCancellationReturnsToIdleWithoutAnAttempt() async throws {
        let controller = PINAuthorizationController()
        let generation = ConnectionGeneration()
        let lease = try await controller.begin(
            generation: generation,
            constraint: Data([0x01])
        )

        try await controller.cancel(lease)

        let snapshot = await controller.snapshot()
        let submissionCount = await controller.submissionCount()
        XCTAssertEqual(snapshot, .idle)
        XCTAssertEqual(submissionCount, 0)
    }

    func testIncorrectAndBlockedResultsNeverRetryAutomatically() async throws {
        for result in [
            PINVerificationResult.incorrect(remainingAttempts: 2),
            .blocked,
        ] {
            let controller = PINAuthorizationController()
            let lease = try await controller.begin(
                generation: ConnectionGeneration(),
                constraint: Data([0x01])
            )

            try await controller.complete(lease, result: result)

            let snapshot = await controller.snapshot()
            let submissionCount = await controller.submissionCount()
            let shouldRetry = await controller.shouldRetryAutomatically()
            XCTAssertEqual(snapshot, .failed(result))
            XCTAssertEqual(submissionCount, 1)
            XCTAssertFalse(shouldRetry)
            await XCTAssertThrowsErrorAsync(try await controller.complete(
                lease,
                result: .accepted
            )) { error in
                XCTAssertEqual(error as? PINAuthorizationError, .staleOperation)
            }
        }
    }

    func testUnknownStatusInvalidatesRatherThanGuessingPINFailure() async throws {
        let controller = PINAuthorizationController()
        let lease = try await controller.begin(
            generation: ConnectionGeneration(),
            constraint: Data([0x01])
        )
        let status = CardStatus(first: 0x69, second: 0x87)

        try await controller.complete(
            lease,
            result: DNIeStatusMapper.pinVerification(status)
        )

        let snapshot = await controller.snapshot()
        let submissionCount = await controller.submissionCount()
        let shouldRetry = await controller.shouldRetryAutomatically()
        XCTAssertEqual(snapshot, .invalid)
        XCTAssertEqual(submissionCount, 1)
        XCTAssertFalse(shouldRetry)
    }

    func testRemovalInvalidatesPendingOperationAndLateCompletionLoses() async throws {
        let controller = PINAuthorizationController()
        let generation = ConnectionGeneration()
        let lease = try await controller.begin(
            generation: generation,
            constraint: Data([0x01])
        )

        await controller.invalidate(generation: generation)

        let snapshot = await controller.snapshot()
        let submissionCount = await controller.submissionCount()
        XCTAssertEqual(snapshot, .invalid)
        XCTAssertEqual(submissionCount, 0)
        await XCTAssertThrowsErrorAsync(
            try await controller.complete(lease, result: .accepted)
        ) { error in
            XCTAssertEqual(error as? PINAuthorizationError, .staleOperation)
        }
    }

    func testRemovalInvalidatesACompletedFailureForTheSameGeneration() async throws {
        let controller = PINAuthorizationController()
        let generation = ConnectionGeneration()
        let lease = try await controller.begin(
            generation: generation,
            constraint: Data([0x01])
        )
        try await controller.complete(
            lease,
            result: .incorrect(remainingAttempts: 2)
        )

        await controller.invalidate(generation: generation)

        let snapshot = await controller.snapshot()
        XCTAssertEqual(snapshot, .invalid)
    }

    func testAcceptanceAuthorizesOnlyTheExactGenerationAndConstraint() async throws {
        let controller = PINAuthorizationController()
        let generation = ConnectionGeneration()
        let constraint = Data([0x01])
        let lease = try await controller.begin(
            generation: generation,
            constraint: constraint
        )

        try await controller.complete(lease, result: .accepted)

        let exactAuthorization = await controller.isAuthorized(
            generation: generation,
            constraint: constraint
        )
        let wrongGenerationAuthorization = await controller.isAuthorized(
            generation: ConnectionGeneration(),
            constraint: constraint
        )
        let wrongConstraintAuthorization = await controller.isAuthorized(
            generation: generation,
            constraint: Data([0x02])
        )
        let submissionCount = await controller.submissionCount()
        XCTAssertTrue(exactAuthorization)
        XCTAssertFalse(wrongGenerationAuthorization)
        XCTAssertFalse(wrongConstraintAuthorization)
        XCTAssertEqual(submissionCount, 1)
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("Expected error")
    } catch {
        errorHandler(error)
    }
}
