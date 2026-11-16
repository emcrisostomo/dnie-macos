import Foundation

public enum CardTransportCommandKind: String, Sendable, Equatable {
    case select
    case readBinary
    case getResponse
    case getChipInformation
    case getChallenge
    case internalAuthenticate
    case externalAuthenticate
    case manageSecurityEnvironment
    case verify
    case computeDigitalSignature
}

public struct CardStatus: Sendable, Equatable {
    public let first: UInt8
    public let second: UInt8

    public init(first: UInt8, second: UInt8) {
        self.first = first
        self.second = second
    }
}

public struct CardTransportRequest: Sendable, Equatable {
    public static let maximumCommandLength = 65_544
    public static let maximumResponseLength = 65_536

    public let kind: CardTransportCommandKind
    public let encodedCommand: Data
    public let maximumResponseLength: Int
    public let structuredCommand: CardStructuredCommand?

    public init(
        kind: CardTransportCommandKind,
        encodedCommand: Data,
        maximumResponseLength: Int
    ) throws {
        guard !encodedCommand.isEmpty,
              encodedCommand.count <= Self.maximumCommandLength,
              (0...Self.maximumResponseLength).contains(maximumResponseLength)
        else {
            throw CardTransportError.invalidBounds
        }
        self.kind = kind
        self.encodedCommand = encodedCommand
        self.maximumResponseLength = maximumResponseLength
        structuredCommand = nil
    }

    public init(
        kind: CardTransportCommandKind,
        structuredCommand: CardStructuredCommand,
        maximumResponseLength: Int
    ) throws {
        let encodedCommand = structuredCommand.encodedCommand
        guard encodedCommand.count <= Self.maximumCommandLength,
              (0...Self.maximumResponseLength).contains(maximumResponseLength) else {
            throw CardTransportError.invalidBounds
        }
        self.kind = kind
        self.encodedCommand = encodedCommand
        self.maximumResponseLength = maximumResponseLength
        self.structuredCommand = structuredCommand
    }
}

public struct CardStructuredCommand: Sendable, Equatable {
    public let cla: UInt8
    public let instruction: UInt8
    public let p1: UInt8
    public let p2: UInt8
    public let data: Data?
    public let expectedResponseLength: Int?

    public init(
        cla: UInt8,
        instruction: UInt8,
        p1: UInt8,
        p2: UInt8,
        data: Data? = nil,
        expectedResponseLength: Int? = nil
    ) throws {
        guard (data?.count ?? 0) <= 255,
              expectedResponseLength.map({ (0...256).contains($0) }) ?? true else {
            throw CardTransportError.invalidBounds
        }
        self.cla = cla
        self.instruction = instruction
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.expectedResponseLength = expectedResponseLength
    }

    public var encodedCommand: Data {
        var encoded = Data([cla, instruction, p1, p2])
        if let data {
            encoded.append(UInt8(data.count))
            encoded.append(data)
        }
        if let expectedResponseLength {
            encoded.append(expectedResponseLength == 256 ? 0 : UInt8(expectedResponseLength))
        }
        return encoded
    }
}

public struct CardTransportResponse: Sendable, Equatable {
    public let data: Data
    public let status: CardStatus

    public init(data: Data, status: CardStatus, maximumLength: Int) throws {
        guard maximumLength >= 0, data.count <= maximumLength else {
            throw CardTransportError.responseTooLarge
        }
        self.data = data
        self.status = status
    }
}

public enum CardTransportError: Error, Sendable, Equatable {
    case invalidBounds
    case staleGeneration
    case cardInvalid
    case timeout
    case reset
    case removed
    case responseTooLarge
    case commandMismatch
    case operationInFlight
    case communication
}

public protocol CardTransport: Sendable {
    func transmit(
        _ request: CardTransportRequest,
        generation: ConnectionGeneration,
        correlationID: CorrelationID
    ) async throws -> CardTransportResponse
}
