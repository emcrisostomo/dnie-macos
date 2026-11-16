import CryptoTokenKit
import DNIeCore
import Foundation

protocol SmartCardEndpoint: Sendable {
    func isValid() async -> Bool
    func transmit(_ request: CardTransportRequest) async throws -> Data
}

actor SmartCardTransport: CardTransport {
    private let endpoint: any SmartCardEndpoint
    private var generation: ConnectionGeneration?
    private var activeCorrelationID: CorrelationID?

    // This initializer must be called only while servicing a
    // TKTokenSessionDelegate method. getSmartCard() supplies the current
    // system-owned exclusive session; this adapter never begins or ends it.
    init(
        session: TKSmartCardTokenSession,
        generation: ConnectionGeneration
    ) throws {
        endpoint = SystemSmartCardEndpoint(card: try session.getSmartCard())
        self.generation = generation
    }

    // Token creation and delegate handlers can receive the already-selected,
    // system-owned card directly. This adapter never begins or ends that session.
    init(cardHandle: SendableSmartCardHandle, generation: ConnectionGeneration) {
        endpoint = SystemSmartCardEndpoint(card: cardHandle.card)
        self.generation = generation
    }

    init(
        endpoint: any SmartCardEndpoint,
        generation: ConnectionGeneration
    ) {
        self.endpoint = endpoint
        self.generation = generation
    }

    func transmit(
        _ request: CardTransportRequest,
        generation expectedGeneration: ConnectionGeneration,
        correlationID: CorrelationID
    ) async throws -> CardTransportResponse {
        guard generation == expectedGeneration else {
            throw CardTransportError.staleGeneration
        }
        guard activeCorrelationID == nil else {
            throw CardTransportError.operationInFlight
        }
        activeCorrelationID = correlationID
        defer {
            if activeCorrelationID == correlationID {
                activeCorrelationID = nil
            }
        }

        guard await endpoint.isValid() else {
            throw CardTransportError.cardInvalid
        }
        guard generation == expectedGeneration else {
            throw CardTransportError.staleGeneration
        }

        let rawResponse: Data
        do {
            rawResponse = try await endpoint.transmit(request)
        } catch {
            guard generation == expectedGeneration else {
                throw CardTransportError.staleGeneration
            }
            guard await endpoint.isValid() else {
                throw CardTransportError.removed
            }
            throw CardTransportError.communication
        }

        guard generation == expectedGeneration else {
            throw CardTransportError.staleGeneration
        }
        guard await endpoint.isValid() else {
            throw CardTransportError.removed
        }
        guard rawResponse.count >= 2 else {
            throw CardTransportError.communication
        }

        let statusOffset = rawResponse.count - 2
        let responseData = Data(rawResponse.prefix(statusOffset))
        guard responseData.count <= request.maximumResponseLength else {
            throw CardTransportError.responseTooLarge
        }
        return try CardTransportResponse(
            data: responseData,
            status: CardStatus(
                first: rawResponse[statusOffset],
                second: rawResponse[statusOffset + 1]
            ),
            maximumLength: request.maximumResponseLength
        )
    }

    func invalidate(generation expectedGeneration: ConnectionGeneration) {
        guard generation == expectedGeneration else { return }
        generation = nil
    }
}

final class SendableSmartCardHandle: @unchecked Sendable {
    let card: TKSmartCard

    init(_ card: TKSmartCard) {
        self.card = card
    }
}

private final class SystemSmartCardEndpoint: SmartCardEndpoint, @unchecked Sendable {
    private let card: TKSmartCard

    init(card: TKSmartCard) {
        self.card = card
    }

    func isValid() async -> Bool {
        card.isValid
    }

    func transmit(_ request: CardTransportRequest) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let reply: @Sendable (Data?, Error?) -> Void = { response, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let response {
                    continuation.resume(returning: response)
                } else {
                    continuation.resume(throwing: CardTransportError.communication)
                }
            }
            if let command = request.structuredCommand {
                card.cla = command.cla
                card.send(
                    ins: command.instruction,
                    p1: command.p1,
                    p2: command.p2,
                    data: command.data,
                    le: command.expectedResponseLength
                ) { response, status, error in
                    do {
                        reply(try SmartCardResponseNormalizer.structured(
                            response: response,
                            status: status,
                            error: error
                        ), nil)
                    } catch {
                        reply(nil, error)
                    }
                }
            } else {
                card.transmit(request.encodedCommand, reply: reply)
            }
        }
    }
}

enum SmartCardResponseNormalizer {
    static func structured(
        response: Data?,
        status: UInt16,
        error: Error?
    ) throws -> Data {
        if status != 0 {
            var rawResponse = response ?? Data()
            rawResponse.append(UInt8(status >> 8))
            rawResponse.append(UInt8(status & 0xFF))
            return rawResponse
        }
        if let error {
            throw error
        }
        throw CardTransportError.communication
    }
}
