import DNIeCore
import XCTest

final class LifecycleStateTests: XCTestCase {
    func testCanonicalLifecycleSequence() async throws {
        let coordinator = TokenCoordinator()
        var state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .absent)

        let generation = await coordinator.beginConnection()
        state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .candidate)

        _ = try await coordinator.perform(
            generation: generation,
            metadata: CardOperationMetadata(kind: .discover)
        ) { true }
        try await coordinator.markRecognized(
            generation: generation,
            profileVersion: ProfileVersion("1.0.0")
        )
        try await coordinator.markPublished(generation: generation)
        state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .publicReady)

        let authorization = try await coordinator.beginAuthorization(
            generation: generation
        )
        state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .authPending)

        try await coordinator.completeAuthorization(authorization)
        state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .authorized)

        _ = try await coordinator.perform(
            generation: generation,
            metadata: CardOperationMetadata(kind: .sign)
        ) { Data([0x01]) }
        state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .authorized)

        _ = try await coordinator.perform(
            generation: generation,
            metadata: CardOperationMetadata(kind: .sign)
        ) { Data([0x02]) }
        state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .authorized)

        await coordinator.invalidate(generation: generation)
        state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .invalid)
    }

    func testCancellationReturnsPendingAuthorizationToPublicReady() async throws {
        let (coordinator, generation) = try await makePublicReadyCoordinator()
        let authorization = try await coordinator.beginAuthorization(
            generation: generation
        )

        try await coordinator.cancelAuthorization(authorization)

        let state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .publicReady)
    }

    func testFailedSignDoesNotRetainAuthorization() async throws {
        let (coordinator, generation) = try await makePublicReadyCoordinator()
        let authorization = try await coordinator.beginAuthorization(
            generation: generation
        )
        try await coordinator.completeAuthorization(authorization)

        await assertCoordinatorError(.invalidTransition) {
            _ = try await coordinator.perform(
                generation: generation,
                metadata: CardOperationMetadata(kind: .sign)
            ) {
                throw TokenCoordinatorError.invalidTransition
            }
        }

        let state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .publicReady)
    }

    func testInvalidTransitionsFailClosed() async throws {
        let coordinator = TokenCoordinator()
        let generation = await coordinator.beginConnection()

        await assertCoordinatorError(.invalidTransition) {
            _ = try await coordinator.beginAuthorization(generation: generation)
        }
        await assertCoordinatorError(.invalidTransition) {
            _ = try await coordinator.perform(
                generation: generation,
                metadata: CardOperationMetadata(kind: .sign)
            ) { Data() }
        }
    }

    func testNewGenerationDisposesPendingAuthorizationAndLateCompletion() async throws {
        let (coordinator, oldGeneration) = try await makePublicReadyCoordinator()
        let oldAuthorization = try await coordinator.beginAuthorization(
            generation: oldGeneration
        )
        let currentGeneration = await coordinator.beginConnection()

        await assertCoordinatorError(.staleAuthorization) {
            try await coordinator.completeAuthorization(oldAuthorization)
        }
        let state = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(state, .candidate)

        try await coordinator.markRecognized(
            generation: currentGeneration,
            profileVersion: ProfileVersion("1.0.0")
        )
    }

    private func makePublicReadyCoordinator() async throws -> (
        TokenCoordinator,
        ConnectionGeneration
    ) {
        let coordinator = TokenCoordinator()
        let generation = await coordinator.beginConnection()
        try await coordinator.markRecognized(
            generation: generation,
            profileVersion: ProfileVersion("1.0.0")
        )
        try await coordinator.markPublished(generation: generation)
        return (coordinator, generation)
    }

    private func assertCoordinatorError(
        _ expected: TokenCoordinatorError,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("Expected coordinator error \(expected)")
        } catch {
            XCTAssertEqual(error as? TokenCoordinatorError, expected)
        }
    }
}
