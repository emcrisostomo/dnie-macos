import Foundation
import XCTest
@testable import DNIeCore

final class PlainStateRecoveryTests: XCTestCase {
    func testAcceptedChannelOffAndPlainFCIComplete() async throws {
        for status in [
            CardStatus(first: 0x66, second: 0x88),
            CardStatus(first: 0x69, second: 0x87),
            CardStatus(first: 0x69, second: 0x88),
        ] {
            let generation = ConnectionGeneration()
            let transport = RecoveryScriptTransport(responses: [
                try response(data: Data(), status: status),
                try response(
                    data: Data([0x6F, 0x02, 0x84, 0x00]),
                    status: CardStatus(first: 0x90, second: 0x00)
                ),
            ])

            try await DNIePlainStateRecovery.execute(
                transport: transport,
                generation: generation
            )

            let requests = await transport.requests()
            XCTAssertEqual(requests.count, 2)
            XCTAssertEqual(requests.map(\.kind), [.select, .select])
            XCTAssertTrue(requests.allSatisfy { $0.structuredCommand != nil })
        }
    }

    func testUnexpectedCandidateStopsBeforeFollowUp() async throws {
        let generation = ConnectionGeneration()
        let status = CardStatus(first: 0x90, second: 0x00)
        let transport = RecoveryScriptTransport(responses: [
            try response(data: Data([0x6F]), status: status),
        ])

        do {
            try await DNIePlainStateRecovery.execute(
                transport: transport,
                generation: generation
            )
            XCTFail("Unexpected channel-off status was accepted")
        } catch {
            XCTAssertEqual(
                error as? PlainStateRecoveryError,
                .unexpectedCandidate(status)
            )
        }
        let requestCount = await transport.requestCount()
        XCTAssertEqual(requestCount, 1)
    }

    func testSynchronizationAcceptsOnlyValidatedAlreadyPlainFCI() async throws {
        let generation = ConnectionGeneration()
        let transport = RecoveryScriptTransport(responses: [
            try response(
                data: Data([0x6F, 0x02, 0x84, 0x00]),
                status: CardStatus(first: 0x90, second: 0x00)
            ),
        ])

        let result = try await DNIePlainStateRecovery.synchronize(
            transport: transport,
            generation: generation
        )

        XCTAssertEqual(result, .alreadyPlain)
        let requests = await transport.requests()
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests.first?.kind, .select)
    }

    func testSynchronizationDeactivatesProtectedStateBeforeValidatedPlainFCI() async throws {
        let generation = ConnectionGeneration()
        let transport = RecoveryScriptTransport(responses: [
            try response(
                data: Data(),
                status: CardStatus(first: 0x69, second: 0x87)
            ),
            try response(
                data: Data([0x6F, 0x02, 0x84, 0x00]),
                status: CardStatus(first: 0x90, second: 0x00)
            ),
        ])

        let result = try await DNIePlainStateRecovery.synchronize(
            transport: transport,
            generation: generation
        )

        XCTAssertEqual(result, .channelDeactivated)
        let requestCount = await transport.requestCount()
        XCTAssertEqual(requestCount, 2)
    }

    func testSynchronizationRejectsInvalidImmediatePlainResponse() async throws {
        let generation = ConnectionGeneration()
        let transport = RecoveryScriptTransport(responses: [
            try response(
                data: Data([0x62, 0x00]),
                status: CardStatus(first: 0x90, second: 0x00)
            ),
        ])

        do {
            _ = try await DNIePlainStateRecovery.synchronize(
                transport: transport,
                generation: generation
            )
            XCTFail("Invalid plain selection was accepted")
        } catch {
            XCTAssertEqual(error as? PlainStateRecoveryError, .invalidPlainResponse)
        }
        let requestCount = await transport.requestCount()
        XCTAssertEqual(requestCount, 1)
    }

    func testCandidateDataAndInvalidFCIFailClosed() async throws {
        let generation = ConnectionGeneration()
        let accepted = CardStatus(first: 0x69, second: 0x87)
        let candidateData = RecoveryScriptTransport(responses: [
            try response(data: Data([0x01]), status: accepted),
        ])
        await assertRecoveryError(.unexpectedCandidateData) {
            try await DNIePlainStateRecovery.execute(
                transport: candidateData,
                generation: generation
            )
        }

        let invalidFCI = RecoveryScriptTransport(responses: [
            try response(data: Data(), status: accepted),
            try response(
                data: Data([0x62, 0x00]),
                status: CardStatus(first: 0x90, second: 0x00)
            ),
        ])
        await assertRecoveryError(.invalidPlainResponse) {
            try await DNIePlainStateRecovery.execute(
                transport: invalidFCI,
                generation: generation
            )
        }
    }

    private func response(
        data: Data,
        status: CardStatus
    ) throws -> CardTransportResponse {
        try CardTransportResponse(
            data: data,
            status: status,
            maximumLength: 8 * 1_024
        )
    }

    private func assertRecoveryError(
        _ expected: PlainStateRecoveryError,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            XCTFail("Expected recovery error \(expected)")
        } catch {
            XCTAssertEqual(error as? PlainStateRecoveryError, expected)
        }
    }
}

private actor RecoveryScriptTransport: CardTransport {
    private let scriptedResponses: [CardTransportResponse]
    private var observedRequests: [CardTransportRequest] = []

    init(responses: [CardTransportResponse]) {
        scriptedResponses = responses
    }

    func transmit(
        _ request: CardTransportRequest,
        generation _: ConnectionGeneration,
        correlationID _: CorrelationID
    ) throws -> CardTransportResponse {
        guard observedRequests.count < scriptedResponses.count else {
            throw CardTransportError.commandMismatch
        }
        let result = scriptedResponses[observedRequests.count]
        observedRequests.append(request)
        return result
    }

    func requests() -> [CardTransportRequest] { observedRequests }
    func requestCount() -> Int { observedRequests.count }
}
