import DNIeCore
import Foundation
import XCTest

final class SmartCardTransportTests: XCTestCase {
    func testRawResponseSeparatesBoundedDataAndStatus() async throws {
        let endpoint = FakeSmartCardEndpoint(outcome: .response(Data([0x21, 0x90, 0x00])))
        let generation = ConnectionGeneration()
        let transport = SmartCardTransport(endpoint: endpoint, generation: generation)

        let response = try await transport.transmit(
            makeRequest(maximumResponseLength: 1),
            generation: generation,
            correlationID: CorrelationID()
        )

        XCTAssertEqual(response.data, Data([0x21]))
        XCTAssertEqual(response.status, CardStatus(first: 0x90, second: 0x00))
        let transmissionCount = await endpoint.transmissionCount()
        XCTAssertEqual(transmissionCount, 1)
    }

    func testStaleGenerationNeverReachesEndpoint() async throws {
        let endpoint = FakeSmartCardEndpoint(outcome: .response(Data([0x90, 0x00])))
        let transport = SmartCardTransport(
            endpoint: endpoint,
            generation: ConnectionGeneration()
        )

        await assertTransportError(.staleGeneration) {
            _ = try await transport.transmit(
                self.makeRequest(maximumResponseLength: 0),
                generation: ConnectionGeneration(),
                correlationID: CorrelationID()
            )
        }
        let transmissionCount = await endpoint.transmissionCount()
        XCTAssertEqual(transmissionCount, 0)
    }

    func testOnlyOneCommandCanBeInFlightAcrossActorReentrancy() async throws {
        let endpoint = GatedSmartCardEndpoint(response: Data([0x90, 0x00]))
        let generation = ConnectionGeneration()
        let transport = SmartCardTransport(endpoint: endpoint, generation: generation)
        let request = try makeRequest(maximumResponseLength: 0)
        let first = Task {
            try await transport.transmit(
                request,
                generation: generation,
                correlationID: CorrelationID()
            )
        }

        await endpoint.waitUntilStarted()
        await assertTransportError(.operationInFlight) {
            _ = try await transport.transmit(
                self.makeRequest(maximumResponseLength: 0),
                generation: generation,
                correlationID: CorrelationID()
            )
        }
        await endpoint.release()
        _ = try await first.value
    }

    func testCommandSlotIsReservedBeforeAwaitedValidityCheck() async throws {
        let endpoint = ValidityGatedSmartCardEndpoint(response: Data([0x90, 0x00]))
        let generation = ConnectionGeneration()
        let transport = SmartCardTransport(endpoint: endpoint, generation: generation)
        let request = try makeRequest(maximumResponseLength: 0)
        let first = Task {
            try await transport.transmit(
                request,
                generation: generation,
                correlationID: CorrelationID()
            )
        }

        await endpoint.waitUntilValidityCheckStarted()
        await assertTransportError(.operationInFlight) {
            _ = try await transport.transmit(
                request,
                generation: generation,
                correlationID: CorrelationID()
            )
        }
        await endpoint.releaseValidityCheck()
        _ = try await first.value
        let transmissionCount = await endpoint.transmissionCount()
        XCTAssertEqual(transmissionCount, 1)
    }

    func testInvalidationWinsOverLateEndpointCompletion() async throws {
        let endpoint = GatedSmartCardEndpoint(response: Data([0x90, 0x00]))
        let generation = ConnectionGeneration()
        let transport = SmartCardTransport(endpoint: endpoint, generation: generation)
        let request = try makeRequest(maximumResponseLength: 0)
        let task = Task {
            try await transport.transmit(
                request,
                generation: generation,
                correlationID: CorrelationID()
            )
        }

        await endpoint.waitUntilStarted()
        await transport.invalidate(generation: generation)
        await endpoint.release()

        do {
            _ = try await task.value
            XCTFail("Late endpoint completion was accepted")
        } catch {
            XCTAssertEqual(error as? CardTransportError, .staleGeneration)
        }
    }

    func testInvalidAndRemovedCardsFailAtDistinctBoundaries() async throws {
        let generation = ConnectionGeneration()
        let invalid = FakeSmartCardEndpoint(
            outcome: .response(Data([0x90, 0x00])),
            isValid: false
        )
        let invalidTransport = SmartCardTransport(endpoint: invalid, generation: generation)
        await assertTransportError(.cardInvalid) {
            _ = try await invalidTransport.transmit(
                self.makeRequest(maximumResponseLength: 0),
                generation: generation,
                correlationID: CorrelationID()
            )
        }

        let removed = FakeSmartCardEndpoint(
            outcome: .responseThenInvalidate(Data([0x90, 0x00]))
        )
        let removedTransport = SmartCardTransport(endpoint: removed, generation: generation)
        await assertTransportError(.removed) {
            _ = try await removedTransport.transmit(
                self.makeRequest(maximumResponseLength: 0),
                generation: generation,
                correlationID: CorrelationID()
            )
        }
    }

    func testMalformedAndOversizedResponsesFailClosed() async throws {
        let generation = ConnectionGeneration()
        let malformed = SmartCardTransport(
            endpoint: FakeSmartCardEndpoint(outcome: .response(Data([0x90]))),
            generation: generation
        )
        await assertTransportError(.communication) {
            _ = try await malformed.transmit(
                self.makeRequest(maximumResponseLength: 0),
                generation: generation,
                correlationID: CorrelationID()
            )
        }

        let oversized = SmartCardTransport(
            endpoint: FakeSmartCardEndpoint(
                outcome: .response(Data([0x01, 0x02, 0x90, 0x00]))
            ),
            generation: generation
        )
        await assertTransportError(.responseTooLarge) {
            _ = try await oversized.transmit(
                self.makeRequest(maximumResponseLength: 1),
                generation: generation,
                correlationID: CorrelationID()
            )
        }
    }

    func testStructuredCardStatusSurvivesFrameworkErrorSideChannel() throws {
        let frameworkError = NSError(
            domain: "synthetic.card-status",
            code: 1
        )

        let raw = try SmartCardResponseNormalizer.structured(
            response: Data([0x21]),
            status: 0x6A82,
            error: frameworkError
        )

        XCTAssertEqual(raw, Data([0x21, 0x6A, 0x82]))
        XCTAssertThrowsError(try SmartCardResponseNormalizer.structured(
            response: nil,
            status: 0,
            error: frameworkError
        ))
    }

    private func makeRequest(maximumResponseLength: Int) throws -> CardTransportRequest {
        try CardTransportRequest(
            kind: .select,
            encodedCommand: Data([0x01]),
            maximumResponseLength: maximumResponseLength
        )
    }

    private func assertTransportError(
        _ expected: CardTransportError,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("Expected transport error \(expected)")
        } catch {
            XCTAssertEqual(error as? CardTransportError, expected)
        }
    }
}

private actor FakeSmartCardEndpoint: SmartCardEndpoint {
    enum Outcome: Sendable {
        case response(Data)
        case responseThenInvalidate(Data)
        case failure
    }

    private let outcome: Outcome
    private var valid: Bool
    private var transmissions = 0

    init(outcome: Outcome, isValid: Bool = true) {
        self.outcome = outcome
        valid = isValid
    }

    func isValid() -> Bool {
        valid
    }

    func transmit(_: CardTransportRequest) throws -> Data {
        transmissions += 1
        switch outcome {
        case let .response(response):
            return response
        case let .responseThenInvalidate(response):
            valid = false
            return response
        case .failure:
            throw CardTransportError.communication
        }
    }

    func transmissionCount() -> Int {
        transmissions
    }
}

private actor GatedSmartCardEndpoint: SmartCardEndpoint {
    private let response: Data
    private let started = TestGate()
    private let completion = TestGate()

    init(response: Data) {
        self.response = response
    }

    func isValid() -> Bool {
        true
    }

    func transmit(_: CardTransportRequest) async -> Data {
        await started.open()
        await completion.wait()
        return response
    }

    func waitUntilStarted() async {
        await started.wait()
    }

    func release() async {
        await completion.open()
    }
}

private actor ValidityGatedSmartCardEndpoint: SmartCardEndpoint {
    private let response: Data
    private let validityStarted = TestGate()
    private let validityCompletion = TestGate()
    private var transmissions = 0

    init(response: Data) {
        self.response = response
    }

    func isValid() async -> Bool {
        await validityStarted.open()
        await validityCompletion.wait()
        return true
    }

    func transmit(_: CardTransportRequest) -> Data {
        transmissions += 1
        return response
    }

    func waitUntilValidityCheckStarted() async {
        await validityStarted.wait()
    }

    func releaseValidityCheck() async {
        await validityCompletion.open()
    }

    func transmissionCount() -> Int {
        transmissions
    }
}

private actor TestGate {
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var isOpen = false

    func wait() async {
        guard !isOpen else { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func open() {
        guard !isOpen else { return }
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending {
            waiter.resume()
        }
    }
}
