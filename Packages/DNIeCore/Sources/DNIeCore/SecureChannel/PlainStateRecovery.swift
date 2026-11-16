import Foundation

public enum PlainStateRecoveryError: Error, Sendable, Equatable {
    case unexpectedCandidate(CardStatus)
    case unexpectedCandidateData
    case unexpectedPlainStatus(CardStatus)
    case invalidPlainResponse
    case responseTooLarge
}

public enum PlainStateSynchronizationResult: Sendable, Equatable {
    case alreadyPlain
    case channelDeactivated
}

public enum DNIePlainStateRecovery {
    private static let acceptedCandidateStatuses: Set<CardStatusKey> = [
        CardStatusKey(0x66, 0x88),
        CardStatusKey(0x69, 0x87),
        CardStatusKey(0x69, 0x88),
    ]
    private static let maximumResponseLength = 8 * 1_024
    private static let maximumContinuationCount = 32
    private static let masterFileName = Data("Master.File".utf8)

    public static func execute(
        transport: any CardTransport,
        generation: ConnectionGeneration
    ) async throws {
        let request = try selectMasterFileRequest()
        let candidate = try await transport.transmit(
            request,
            generation: generation,
            correlationID: CorrelationID()
        )
        guard acceptedCandidateStatuses.contains(CardStatusKey(candidate.status)) else {
            throw PlainStateRecoveryError.unexpectedCandidate(candidate.status)
        }
        guard candidate.data.isEmpty else {
            throw PlainStateRecoveryError.unexpectedCandidateData
        }

        try await requirePlainSelection(
            initial: nil,
            request: request,
            transport: transport,
            generation: generation
        )
    }

    public static func synchronize(
        transport: any CardTransport,
        generation: ConnectionGeneration
    ) async throws -> PlainStateSynchronizationResult {
        let request = try selectMasterFileRequest()
        let candidate = try await transport.transmit(
            request,
            generation: generation,
            correlationID: CorrelationID()
        )
        if acceptedCandidateStatuses.contains(CardStatusKey(candidate.status)) {
            guard candidate.data.isEmpty else {
                throw PlainStateRecoveryError.unexpectedCandidateData
            }
            try await requirePlainSelection(
                initial: nil,
                request: request,
                transport: transport,
                generation: generation
            )
            return .channelDeactivated
        }

        try await requirePlainSelection(
            initial: candidate,
            request: request,
            transport: transport,
            generation: generation
        )
        return .alreadyPlain
    }

    private static func requirePlainSelection(
        initial: CardTransportResponse?,
        request: CardTransportRequest,
        transport: any CardTransport,
        generation: ConnectionGeneration
    ) async throws {
        var result = if let initial {
            initial
        } else {
            try await transport.transmit(
                request,
                generation: generation,
                correlationID: CorrelationID()
            )
        }
        var response = result.data
        var continuationCount = 0
        while result.status.first == 0x61 {
            guard continuationCount < maximumContinuationCount else {
                throw PlainStateRecoveryError.responseTooLarge
            }
            let length = result.status.second == 0 ? 256 : Int(result.status.second)
            result = try await transport.transmit(
                try CardTransportRequest(
                    kind: .getResponse,
                    structuredCommand: CardStructuredCommand(
                        cla: 0,
                        instruction: 0xC0,
                        p1: 0,
                        p2: 0,
                        expectedResponseLength: length
                    ),
                    maximumResponseLength: maximumResponseLength
                ),
                generation: generation,
                correlationID: CorrelationID()
            )
            guard response.count + result.data.count <= maximumResponseLength else {
                throw PlainStateRecoveryError.responseTooLarge
            }
            response.append(result.data)
            continuationCount += 1
        }
        guard result.status == CardStatus(first: 0x90, second: 0x00) else {
            throw PlainStateRecoveryError.unexpectedPlainStatus(result.status)
        }
        guard response.first == 0x6F else {
            throw PlainStateRecoveryError.invalidPlainResponse
        }
    }

    private static func selectMasterFileRequest() throws -> CardTransportRequest {
        try CardTransportRequest(
            kind: .select,
            structuredCommand: CardStructuredCommand(
                cla: 0,
                instruction: 0xA4,
                p1: 0x04,
                p2: 0,
                data: masterFileName,
                expectedResponseLength: 256
            ),
            maximumResponseLength: maximumResponseLength
        )
    }
}

private struct CardStatusKey: Hashable {
    let first: UInt8
    let second: UInt8

    init(_ first: UInt8, _ second: UInt8) {
        self.first = first
        self.second = second
    }

    init(_ status: CardStatus) {
        first = status.first
        second = status.second
    }
}
