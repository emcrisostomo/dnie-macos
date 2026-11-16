import Foundation

public enum PINSecureChannelError: Error, Sendable, Equatable {
    case invalidPassword
    case invalidState
    case automaticRetryProhibited
    case invalidResponse
    case invalidAuthentication
    case outerStatus(CardStatus)
}

public enum PINSecureChannelLifecycleState: Sendable, Equatable {
    case ready
    case verified
    case destroyed
}

public actor DNIePINSecureChannel {
    private static let maximumProtectedResponseLength = 8 * 1_024
    private static let maximumContinuationCount = 32

    private let base: any CardTransport
    private let generation: ConnectionGeneration
    private var channel: EphemeralChannelState?
    private var lifecycle: PINSecureChannelLifecycleState = .ready
    private var submissions = 0

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
        if var channel {
            channel.destroy()
        }
    }

    public func verify(password input: Data) async throws -> PINVerificationResult {
        guard lifecycle == .ready, channel != nil else {
            throw submissions == 0
                ? PINSecureChannelError.invalidState
                : PINSecureChannelError.automaticRetryProhibited
        }
        guard !input.isEmpty, input.count <= UInt8.max else {
            throw PINSecureChannelError.invalidPassword
        }
        submissions += 1
        var password = input
        defer { CryptoPrimitives.secureZero(&password) }

        do {
            let result = try await transmitVerify(password: password)
            switch result {
            case .accepted:
                lifecycle = .verified
            case .incorrect, .blocked, .unknown:
                destroy()
            }
            return result
        } catch {
            destroy()
            throw error
        }
    }

    public func invalidate(generation expectedGeneration: ConnectionGeneration) {
        guard generation == expectedGeneration else { return }
        destroy()
    }

    public func snapshot() -> PINSecureChannelLifecycleState {
        lifecycle
    }

    public func submissionCount() -> Int {
        submissions
    }

    func consumeVerifiedState() throws -> EphemeralChannelState {
        guard lifecycle == .verified, let channel else {
            throw PINSecureChannelError.invalidState
        }
        self.channel = nil
        lifecycle = .destroyed
        return channel
    }

    private func transmitVerify(password: Data) async throws -> PINVerificationResult {
        guard var channel else { throw PINSecureChannelError.invalidState }
        defer { self.channel = channel }

        let commandCounter = try channel.nextCounter()
        let body = try channel.withKeys { encryptionKey, macKey in
            let ciphertext = try CryptoPrimitives.dnieEncrypt(
                key: encryptionKey,
                incrementedCounter: commandCounter,
                plaintext: password
            )
            let encryptedObject = SecureMessagingTLV.encode(
                tag: 0x87,
                value: Data([0x01]) + ciphertext
            )
            let paddedHeader = try CryptoPrimitives.iso7816Pad(Data([
                0x0C, 0x20, 0x00, 0x00,
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
        guard body.count <= UInt8.max else {
            throw PINSecureChannelError.invalidPassword
        }
        let encoded = Data([0x0C, 0x20, 0x00, 0x00, UInt8(body.count)]) + body
        let correlationID = CorrelationID()
        var outer = try await base.transmit(
            CardTransportRequest(
                kind: .verify,
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
                throw PINSecureChannelError.invalidResponse
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
                throw PINSecureChannelError.invalidResponse
            }
            protectedResponse.append(outer.data)
            continuationCount += 1
        }
        guard outer.status == CardStatus(first: 0x90, second: 0x00) else {
            throw PINSecureChannelError.outerStatus(outer.status)
        }

        let responseCounter = try channel.nextCounter()
        let objects = try SecureMessagingTLV.parseAll(protectedResponse)
        guard objects.map(\.tag) == [0x99, 0x8E],
              objects[0].value.count == 2,
              objects[1].value.count == 8 else {
            throw PINSecureChannelError.invalidResponse
        }
        let macInput = try CryptoPrimitives.iso7816Pad(objects[0].encoded)
        let authenticated = try channel.withKeys { _, macKey in
            CryptoPrimitives.verifyTag(
                expected: try CryptoPrimitives.dnieMAC(
                    key: macKey,
                    incrementedCounter: responseCounter,
                    paddedMessage: macInput
                ),
                actual: objects[1].value
            )
        }
        guard authenticated else {
            throw PINSecureChannelError.invalidAuthentication
        }
        return DNIeStatusMapper.pinVerification(CardStatus(
            first: objects[0].value[0],
            second: objects[0].value[1]
        ))
    }

    private func destroy() {
        if var channel {
            channel.destroy()
            self.channel = nil
        }
        lifecycle = .destroyed
    }
}
