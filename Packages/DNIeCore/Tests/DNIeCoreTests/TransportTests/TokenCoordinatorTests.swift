import DNIeCore
import XCTest

final class TokenCoordinatorTests: XCTestCase {
    func testNewConnectionMakesOldGenerationStale() async throws {
        let coordinator = TokenCoordinator()
        let old = await coordinator.beginConnection()
        let current = await coordinator.beginConnection()

        do {
            try await coordinator.markRecognized(
                generation: old,
                profileVersion: ProfileVersion("1.0.0")
            )
            XCTFail("Old generation was accepted")
        } catch {
            XCTAssertEqual(error as? TokenCoordinatorError, .staleGeneration)
        }

        try await coordinator.markRecognized(
            generation: current,
            profileVersion: ProfileVersion("1.0.0")
        )
    }

    func testInvalidationDiscardsLateCompletion() async throws {
        let coordinator = TokenCoordinator()
        let generation = await coordinator.beginConnection()
        let gate = AsyncGate()
        let started = expectation(description: "operation started")

        let task = Task {
            try await coordinator.perform(
                generation: generation,
                metadata: CardOperationMetadata(kind: .discover)
            ) {
                started.fulfill()
                await gate.wait()
                return 7
            }
        }

        await fulfillment(of: [started], timeout: 2)
        await coordinator.invalidate(generation: generation)
        await gate.open()

        do {
            _ = try await task.value
            XCTFail("Late completion was accepted")
        } catch {
            XCTAssertEqual(error as? TokenCoordinatorError, .staleCompletion)
        }
    }
}

private actor AsyncGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var isOpen = false

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { continuation = $0 }
    }

    func open() {
        isOpen = true
        continuation?.resume()
        continuation = nil
    }
}
