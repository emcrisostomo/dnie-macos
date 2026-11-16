import DNIeCore
import Foundation
import XCTest

final class CardTransportContractTests: XCTestCase {
    func testSuccessPreservesRequestContextResponseAndStatus() async throws {
        let response = try CardTransportResponse(
            data: Data([0x21, 0x43]),
            status: CardStatus(first: 0x90, second: 0x00),
            maximumLength: 8
        )
        let transport = ScriptedCardTransport(steps: [.response(response)])
        let request = try makeRequest(maximumResponseLength: 8)
        let generation = ConnectionGeneration()
        let correlationID = CorrelationID()

        let received = try await transport.transmit(
            request,
            generation: generation,
            correlationID: correlationID
        )

        XCTAssertEqual(received, response)
        let transmissions = await transport.recordedTransmissions()
        XCTAssertEqual(
            transmissions,
            [RecordedTransmission(
                request: request,
                generation: generation,
                correlationID: correlationID
            )]
        )
    }

    func testShortResponseIsPreservedForTheProfileToValidate() async throws {
        let response = try CardTransportResponse(
            data: Data(),
            status: CardStatus(first: 0x90, second: 0x00),
            maximumLength: 8
        )
        let transport = ScriptedCardTransport(steps: [.response(response)])

        let received = try await transport.transmit(
            makeRequest(maximumResponseLength: 8),
            generation: ConnectionGeneration(),
            correlationID: CorrelationID()
        )

        XCTAssertTrue(received.data.isEmpty)
        XCTAssertEqual(received.status, CardStatus(first: 0x90, second: 0x00))
    }

    func testUnknownStatusIsNotGuessedOrRemappedByTransport() async throws {
        let unknown = CardStatus(first: 0x6F, second: 0x7E)
        let response = try CardTransportResponse(
            data: Data([0x01]),
            status: unknown,
            maximumLength: 8
        )
        let transport = ScriptedCardTransport(steps: [.response(response)])

        let received = try await transport.transmit(
            makeRequest(maximumResponseLength: 8),
            generation: ConnectionGeneration(),
            correlationID: CorrelationID()
        )

        XCTAssertEqual(received.status, unknown)
        XCTAssertEqual(received.data, Data([0x01]))
    }

    func testTimeoutResetAndRemovalRemainDistinctTerminalErrors() async throws {
        for expected in [
            CardTransportError.timeout,
            CardTransportError.reset,
            CardTransportError.removed,
        ] {
            let transport = ScriptedCardTransport(steps: [.failure(expected)])

            do {
                _ = try await transport.transmit(
                    makeRequest(maximumResponseLength: 8),
                    generation: ConnectionGeneration(),
                    correlationID: CorrelationID()
                )
                XCTFail("Expected terminal transport error \(expected)")
            } catch {
                XCTAssertEqual(error as? CardTransportError, expected)
            }
        }
    }

    func testLateTransportCompletionCannotWinAfterInvalidation() async throws {
        let coordinator = TokenCoordinator()
        let generation = await coordinator.beginConnection()
        let transport = GatedCardTransport(
            response: try CardTransportResponse(
                data: Data([0x01]),
                status: CardStatus(first: 0x90, second: 0x00),
                maximumLength: 8
            )
        )
        let request = try makeRequest(maximumResponseLength: 8)
        let correlationID = CorrelationID()

        let task = Task {
            try await coordinator.perform(
                generation: generation,
                metadata: CardOperationMetadata(
                    kind: .discover,
                    correlationID: correlationID
                )
            ) {
                try await transport.transmit(
                    request,
                    generation: generation,
                    correlationID: correlationID
                )
            }
        }

        await transport.waitUntilStarted()
        await coordinator.invalidate(generation: generation)
        await transport.releaseCompletion()

        do {
            _ = try await task.value
            XCTFail("Late transport completion was accepted")
        } catch {
            XCTAssertEqual(error as? TokenCoordinatorError, .staleCompletion)
        }
    }

    private func makeRequest(maximumResponseLength: Int) throws -> CardTransportRequest {
        try CardTransportRequest(
            kind: .select,
            encodedCommand: Data([0x01]),
            maximumResponseLength: maximumResponseLength
        )
    }
}

private struct RecordedTransmission: Sendable, Equatable {
    let request: CardTransportRequest
    let generation: ConnectionGeneration
    let correlationID: CorrelationID
}

private actor ScriptedCardTransport: CardTransport {
    enum Step: Sendable {
        case response(CardTransportResponse)
        case failure(CardTransportError)
    }

    private var steps: [Step]
    private var transmissions: [RecordedTransmission] = []

    init(steps: [Step]) {
        self.steps = steps
    }

    func transmit(
        _ request: CardTransportRequest,
        generation: ConnectionGeneration,
        correlationID: CorrelationID
    ) async throws -> CardTransportResponse {
        transmissions.append(RecordedTransmission(
            request: request,
            generation: generation,
            correlationID: correlationID
        ))
        guard !steps.isEmpty else {
            throw CardTransportError.commandMismatch
        }

        switch steps.removeFirst() {
        case let .response(response):
            return response
        case let .failure(error):
            throw error
        }
    }

    func recordedTransmissions() -> [RecordedTransmission] {
        transmissions
    }
}

private actor GatedCardTransport: CardTransport {
    private let response: CardTransportResponse
    private let started = OneShotGate()
    private let completion = OneShotGate()

    init(response: CardTransportResponse) {
        self.response = response
    }

    func transmit(
        _: CardTransportRequest,
        generation _: ConnectionGeneration,
        correlationID _: CorrelationID
    ) async throws -> CardTransportResponse {
        await started.open()
        await completion.wait()
        return response
    }

    func waitUntilStarted() async {
        await started.wait()
    }

    func releaseCompletion() async {
        await completion.open()
    }
}

private actor OneShotGate {
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var isOpen = false

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func open() {
        guard !isOpen else { return }
        isOpen = true
        let continuations = waiters
        waiters.removeAll()
        for continuation in continuations {
            continuation.resume()
        }
    }
}
