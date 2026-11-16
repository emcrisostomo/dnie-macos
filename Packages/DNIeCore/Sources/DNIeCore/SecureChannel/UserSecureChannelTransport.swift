import Foundation

public enum SecureChannelResponseFailure: String, Sendable, Equatable {
    case continuationLimit
    case aggregateLimit
    case empty
    case malformedTLV
    case malformedTLVAtExactDataLength
    case objectSequence
    case statusLength
    case macLength
    case encryptedDataMarker
    case missingEncryptedDataOnSuccess
}

public enum SecureChannelTransportError: Error, Sendable, Equatable {
    case invalidRequest
    case invalidResponse(SecureChannelResponseFailure)
    case invalidAuthentication
    case destroyedState
    case outerStatus(CardStatus)
    case innerStatus(CardStatus)
}

public enum SecureChannelLifecycleState: Sendable, Equatable {
    case active
    case destroyed
}

public actor DNIeUserSecureChannelTransport: UserSecureCardTransport {
    private static let maximumProtectedResponseLength = 8 * 1_024
    private static let maximumContinuationCount = 32

    private var base: any CardTransport
    private let generation: ConnectionGeneration
    private var channel: EphemeralChannelState
    private var lifecycle: SecureChannelLifecycleState = .active

    init(
        base: any CardTransport,
        generation: ConnectionGeneration,
        channel: EphemeralChannelState
    ) {
        self.base = base
        self.generation = generation
        self.channel = channel
    }

    deinit {
        channel.destroy()
    }

    public func transmit(
        _ request: CardTransportRequest,
        generation expectedGeneration: ConnectionGeneration,
        correlationID: CorrelationID
    ) async throws -> CardTransportResponse {
        guard generation == expectedGeneration else {
            throw CardTransportError.staleGeneration
        }
        guard lifecycle == .active else {
            throw SecureChannelTransportError.destroyedState
        }

        do {
            return try await transmitProtected(
                request,
                correlationID: correlationID
            )
        } catch {
            destroy()
            throw error
        }
    }

    public func invalidate(generation expectedGeneration: ConnectionGeneration) {
        guard generation == expectedGeneration else { return }
        destroy()
    }

    public func rebind(
        to base: any CardTransport,
        generation expectedGeneration: ConnectionGeneration
    ) throws {
        guard generation == expectedGeneration else {
            throw CardTransportError.staleGeneration
        }
        guard lifecycle == .active else {
            throw SecureChannelTransportError.destroyedState
        }
        self.base = base
    }

    public func snapshot() -> SecureChannelLifecycleState {
        lifecycle
    }

    private func transmitProtected(
        _ request: CardTransportRequest,
        correlationID: CorrelationID
    ) async throws -> CardTransportResponse {
        guard let command = request.structuredCommand,
              command.cla == 0x00,
              let plaintext = command.data,
              !plaintext.isEmpty,
              plaintext.count <= UInt8.max else {
            throw SecureChannelTransportError.invalidRequest
        }

        let commandCounter = try channel.nextCounter()
        let protectedBody = try channel.withKeys { encryptionKey, macKey in
            let ciphertext = try CryptoPrimitives.dnieEncrypt(
                key: encryptionKey,
                incrementedCounter: commandCounter,
                plaintext: plaintext
            )
            let encryptedObject = SecureMessagingTLV.encode(
                tag: 0x87,
                value: Data([0x01]) + ciphertext
            )
            let paddedHeader = try CryptoPrimitives.iso7816Pad(Data([
                0x0C, command.instruction, command.p1, command.p2,
            ]))
            let macInput = try CryptoPrimitives.iso7816Pad(
                paddedHeader + encryptedObject
            )
            let tag = try CryptoPrimitives.dnieMAC(
                key: macKey,
                incrementedCounter: commandCounter,
                paddedMessage: macInput
            )
            return encryptedObject + SecureMessagingTLV.encode(tag: 0x8E, value: tag)
        }
        guard protectedBody.count <= UInt8.max else {
            throw SecureChannelTransportError.invalidRequest
        }

        let encoded = Data([
            0x0C,
            command.instruction,
            command.p1,
            command.p2,
            UInt8(protectedBody.count),
        ]) + protectedBody
        var outer = try await base.transmit(
            CardTransportRequest(
                kind: request.kind,
                encodedCommand: encoded,
                maximumResponseLength: Self.maximumProtectedResponseLength
            ),
            generation: generation,
            correlationID: correlationID
        )
        var protectedResponse = outer.data
        var continuationCount = 0
        while outer.status.first == 0x61 {
            guard continuationCount < Self.maximumContinuationCount else {
                throw SecureChannelTransportError.invalidResponse(.continuationLimit)
            }
            outer = try await base.transmit(
                CardTransportRequest(
                    kind: .getResponse,
                    encodedCommand: Data([
                        0x00, 0xC0, 0x00, 0x00, outer.status.second,
                    ]),
                    maximumResponseLength: Self.maximumProtectedResponseLength
                ),
                generation: generation,
                correlationID: correlationID
            )
            guard protectedResponse.count + outer.data.count
                    <= Self.maximumProtectedResponseLength else {
                throw SecureChannelTransportError.invalidResponse(.aggregateLimit)
            }
            protectedResponse.append(outer.data)
            continuationCount += 1
        }
        guard outer.status == CardStatus(first: 0x90, second: 0x00) else {
            throw SecureChannelTransportError.outerStatus(outer.status)
        }

        let responseCounter = try channel.nextCounter()
        let expectsData = request.maximumResponseLength > 0
        guard !protectedResponse.isEmpty else {
            throw SecureChannelTransportError.invalidResponse(.empty)
        }
        let objects: [SecureMessagingTLV]
        do {
            objects = try SecureMessagingTLV.parseAll(protectedResponse)
        } catch {
            let failure: SecureChannelResponseFailure =
                expectsData && protectedResponse.count == request.maximumResponseLength
                ? .malformedTLVAtExactDataLength
                : .malformedTLV
            throw SecureChannelTransportError.invalidResponse(failure)
        }
        let tags = objects.map(\.tag)
        let dataAndStatusResponse = tags == [0x87, 0x99, 0x8E]
        let statusOnlyResponse = tags == [0x99, 0x8E]
        guard statusOnlyResponse || (expectsData && dataAndStatusResponse) else {
            throw SecureChannelTransportError.invalidResponse(.objectSequence)
        }
        guard let statusObject = objects.first(where: { $0.tag == 0x99 }),
              statusObject.value.count == 2 else {
            throw SecureChannelTransportError.invalidResponse(.statusLength)
        }
        guard let macObject = objects.last,
              macObject.value.count == 8 else {
            throw SecureChannelTransportError.invalidResponse(.macLength)
        }

        let macInput = try CryptoPrimitives.iso7816Pad(
            objects.dropLast().reduce(into: Data()) { $0.append($1.encoded) }
        )
        let authenticated = try channel.withKeys { _, macKey in
            let expected = try CryptoPrimitives.dnieMAC(
                key: macKey,
                incrementedCounter: responseCounter,
                paddedMessage: macInput
            )
            return CryptoPrimitives.verifyTag(
                expected: expected,
                actual: macObject.value
            )
        }
        guard authenticated else {
            throw SecureChannelTransportError.invalidAuthentication
        }

        let innerStatus = CardStatus(
            first: statusObject.value[0],
            second: statusObject.value[1]
        )
        guard innerStatus == CardStatus(first: 0x90, second: 0x00) else {
            throw SecureChannelTransportError.innerStatus(innerStatus)
        }
        let responseData: Data
        if expectsData {
            guard dataAndStatusResponse else {
                throw SecureChannelTransportError.invalidResponse(
                    .missingEncryptedDataOnSuccess
                )
            }
            guard let encryptedObject = objects.first,
                  encryptedObject.value.first == 0x01 else {
                throw SecureChannelTransportError.invalidResponse(.encryptedDataMarker)
            }
            responseData = try channel.withKeys { encryptionKey, _ in
                try CryptoPrimitives.dnieDecrypt(
                    key: encryptionKey,
                    incrementedCounter: responseCounter,
                    ciphertext: Data(encryptedObject.value.dropFirst())
                )
            }
        } else {
            responseData = Data()
        }
        return try CardTransportResponse(
            data: responseData,
            status: innerStatus,
            maximumLength: request.maximumResponseLength
        )
    }

    private func destroy() {
        guard lifecycle == .active else { return }
        channel.destroy()
        lifecycle = .destroyed
    }
}

struct SecureMessagingTLV: Sendable, Equatable {
    let tag: Int
    let value: Data
    let encoded: Data

    static func encode(tag: UInt8, value: Data) -> Data {
        precondition(value.count <= 0xFFFF)
        let length: Data
        if value.count < 0x80 {
            length = Data([UInt8(value.count)])
        } else if value.count <= 0xFF {
            length = Data([0x81, UInt8(value.count)])
        } else {
            length = Data([
                0x82, UInt8(value.count >> 8), UInt8(value.count & 0xFF),
            ])
        }
        return Data([tag]) + length + value
    }

    static func parseAll(_ data: Data) throws -> [SecureMessagingTLV] {
        var index = 0
        var result: [SecureMessagingTLV] = []
        while index < data.count {
            result.append(try parseOne(data, index: &index))
        }
        return result
    }

    static func parsePrefix(_ data: Data) throws -> SecureMessagingTLV {
        var index = 0
        return try parseOne(data, index: &index)
    }

    private static func parseOne(
        _ data: Data,
        index: inout Int
    ) throws -> SecureMessagingTLV {
        let start = index
        let firstTag = try readByte(data, index: &index)
        var tag = Int(firstTag)
        if tag & 0x1F == 0x1F {
            repeat {
                let byte = try readByte(data, index: &index)
                tag = (tag << 8) | Int(byte)
                if byte & 0x80 == 0 { break }
            } while true
        }
        let firstLength = try readByte(data, index: &index)
        let length: Int
        if firstLength & 0x80 == 0 {
            length = Int(firstLength)
        } else {
            let count = Int(firstLength & 0x7F)
            guard (1...2).contains(count) else {
                throw SecureChannelTransportError.invalidResponse(.malformedTLV)
            }
            var decoded = 0
            for _ in 0..<count {
                decoded = (decoded << 8) | Int(try readByte(data, index: &index))
            }
            length = decoded
        }
        guard length >= 0, index + length <= data.count else {
            throw SecureChannelTransportError.invalidResponse(.malformedTLV)
        }
        let value = Data(data[index..<(index + length)])
        index += length
        return SecureMessagingTLV(
            tag: tag,
            value: value,
            encoded: Data(data[start..<index])
        )
    }

    private static func readByte(_ data: Data, index: inout Int) throws -> UInt8 {
        guard index < data.count else {
            throw SecureChannelTransportError.invalidResponse(.malformedTLV)
        }
        defer { index += 1 }
        return data[index]
    }
}
