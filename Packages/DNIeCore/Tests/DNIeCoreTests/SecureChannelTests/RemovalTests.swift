import Foundation
import XCTest
@testable import DNIeCore

final class RemovalTests: XCTestCase {
    private let encryptionKey = Data(removalHex: "7252e29d5ab69ed89924263128e7e997")
    private let macKey = Data(removalHex: "e7fa91b49f6e83703a0f9c63708bcd6d")
    private let counter = Data(removalHex: "44ced6da57b5ae2af1f13263f6a104d9")

    func testRemovalDuringDiscoveryDisposesLateCompletion() async throws {
        let coordinator = TokenCoordinator()
        let generation = await coordinator.beginConnection()
        let gate = RemovalGate()
        let started = expectation(description: "discovery started")
        let discovery = Task {
            try await coordinator.perform(
                generation: generation,
                metadata: CardOperationMetadata(kind: .discover)
            ) {
                started.fulfill()
                await gate.wait()
                return Data([0x01])
            }
        }

        await fulfillment(of: [started], timeout: 2)
        await coordinator.invalidate(generation: generation)
        await gate.open()

        do {
            _ = try await discovery.value
            XCTFail("Removed discovery completion was accepted")
        } catch {
            XCTAssertEqual(error as? TokenCoordinatorError, .staleCompletion)
        }
        let lifecycle = await coordinator.lifecycleSnapshot()
        XCTAssertEqual(lifecycle, .invalid)
    }

    func testRemovalDuringPendingPINInvalidatesLeaseWithoutSubmission() async throws {
        let controller = PINAuthorizationController()
        let generation = ConnectionGeneration()
        let lease = try await controller.begin(
            generation: generation,
            constraint: Data("constraint".utf8)
        )

        await controller.invalidate(generation: generation)

        do {
            try await controller.complete(lease, result: .accepted)
            XCTFail("Removed PIN callback was accepted")
        } catch {
            XCTAssertEqual(error as? PINAuthorizationError, .staleOperation)
        }
        let state = await controller.snapshot()
        let submissions = await controller.submissionCount()
        XCTAssertEqual(state, .invalid)
        XCTAssertEqual(submissions, 0)
    }

    func testRemovalDuringPINCommandDestroysEphemeralChannel() async throws {
        let generation = ConnectionGeneration()
        let transport = RemovalTransport()
        let channel = try DNIePINSecureChannel(
            base: transport,
            generation: generation,
            channel: makeState()
        )

        do {
            _ = try await channel.verify(password: Data("Public7!".utf8))
            XCTFail("Removed PIN command completed")
        } catch {
            XCTAssertEqual(error as? CardTransportError, .removed)
        }
        let lifecycle = await channel.snapshot()
        XCTAssertEqual(lifecycle, .destroyed)
    }

    func testRemovalDuringSigningDestroysEphemeralChannel() async throws {
        let generation = ConnectionGeneration()
        let transport = RemovalTransport()
        let channel = try DNIeUserSecureChannelTransport(
            base: transport,
            generation: generation,
            channel: makeState()
        )

        do {
            _ = try await DNIeSigning.signSHA256Digest(
                Data(repeating: 0x5A, count: 32),
                keyReference: 0x01,
                protectedTransport: channel,
                generation: generation
            )
            XCTFail("Removed signing command completed")
        } catch {
            XCTAssertEqual(error as? CardTransportError, .removed)
        }
        let lifecycle = await channel.snapshot()
        XCTAssertEqual(lifecycle, .destroyed)
    }

    private func makeState() throws -> EphemeralChannelState {
        try EphemeralChannelState(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter
        )
    }
}

private actor RemovalGate {
    private var continuation: CheckedContinuation<Void, Never>?

    func wait() async {
        await withCheckedContinuation { continuation = $0 }
    }

    func open() {
        continuation?.resume()
        continuation = nil
    }
}

private actor RemovalTransport: CardTransport {
    func transmit(
        _: CardTransportRequest,
        generation _: ConnectionGeneration,
        correlationID _: CorrelationID
    ) throws -> CardTransportResponse {
        throw CardTransportError.removed
    }
}

private extension Data {
    init(removalHex: String) {
        self.init(stride(from: 0, to: removalHex.count, by: 2).map { offset in
            let start = removalHex.index(removalHex.startIndex, offsetBy: offset)
            let end = removalHex.index(start, offsetBy: 2)
            return UInt8(removalHex[start..<end], radix: 16)!
        })
    }
}
