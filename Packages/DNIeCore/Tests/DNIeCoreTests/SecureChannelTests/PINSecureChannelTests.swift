import Foundation
import XCTest
@testable import DNIeCore

final class PINSecureChannelTests: XCTestCase {
    private let encryptionKey = Data(pinHex: "7252e29d5ab69ed89924263128e7e997")
    private let macKey = Data(pinHex: "e7fa91b49f6e83703a0f9c63708bcd6d")
    private let counter = Data(pinHex: "44ced6da57b5ae2af1f13263f6a104d9")

    func testAcceptedVerifyIsOneProtectedSubmissionAndStateCanTransferOnce() async throws {
        let generation = ConnectionGeneration()
        let peer = try PINPeer(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter,
            status: CardStatus(first: 0x90, second: 0x00)
        )
        let channel = try makeChannel(base: peer, generation: generation)

        let result = try await channel.verify(password: Data("Public7!".utf8))

        XCTAssertEqual(result, .accepted)
        let lifecycle = await channel.snapshot()
        let submissions = await channel.submissionCount()
        let observedInput = await peer.observedInput()
        XCTAssertEqual(lifecycle, .verified)
        XCTAssertEqual(submissions, 1)
        XCTAssertEqual(observedInput, Data("Public7!".utf8))
        _ = try await channel.consumeVerifiedState()
        let consumedLifecycle = await channel.snapshot()
        XCTAssertEqual(consumedLifecycle, .destroyed)
        await XCTAssertThrowsPINError(
            try await channel.consumeVerifiedState(),
            expected: .invalidState
        )
    }

    func testDocumentedIncorrectAndBlockedStatusesDestroyWithoutRetry() async throws {
        for (status, expected) in [
            (CardStatus(first: 0x63, second: 0xC2), PINVerificationResult.incorrect(remainingAttempts: 2)),
            (CardStatus(first: 0x69, second: 0x83), PINVerificationResult.blocked),
        ] {
            let generation = ConnectionGeneration()
            let peer = try PINPeer(
                encryptionKey: encryptionKey,
                macKey: macKey,
                counter: counter,
                status: status
            )
            let channel = try makeChannel(base: peer, generation: generation)

            let result = try await channel.verify(password: Data("Public7!".utf8))
            XCTAssertEqual(result, expected)
            let lifecycle = await channel.snapshot()
            let submissions = await channel.submissionCount()
            XCTAssertEqual(lifecycle, .destroyed)
            XCTAssertEqual(submissions, 1)
            await XCTAssertThrowsPINError(
                try await channel.verify(password: Data("Public7!".utf8)),
                expected: .automaticRetryProhibited
            )
            let requestCount = await peer.requestCount()
            XCTAssertEqual(requestCount, 1)
        }
    }

    func testUnknownOrTamperedResponseDestroysWithoutGuessing() async throws {
        let unknownGeneration = ConnectionGeneration()
        let unknownPeer = try PINPeer(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter,
            status: CardStatus(first: 0x69, second: 0x87)
        )
        let unknownChannel = try makeChannel(
            base: unknownPeer,
            generation: unknownGeneration
        )
        let unknown = try await unknownChannel.verify(password: Data("Public7!".utf8))
        XCTAssertEqual(unknown, .unknown(CardStatus(first: 0x69, second: 0x87)))
        let unknownLifecycle = await unknownChannel.snapshot()
        XCTAssertEqual(unknownLifecycle, .destroyed)

        let tamperGeneration = ConnectionGeneration()
        let tamperedPeer = try PINPeer(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter,
            status: CardStatus(first: 0x90, second: 0x00),
            tamperResponse: true
        )
        let tamperedChannel = try makeChannel(
            base: tamperedPeer,
            generation: tamperGeneration
        )
        do {
            _ = try await tamperedChannel.verify(password: Data("Public7!".utf8))
            XCTFail("Expected MAC rejection")
        } catch {
            XCTAssertEqual(error as? PINSecureChannelError, .invalidAuthentication)
        }
        let tamperedLifecycle = await tamperedChannel.snapshot()
        XCTAssertEqual(tamperedLifecycle, .destroyed)
    }

    func testRemovalAndExplicitInvalidationAreTerminal() async throws {
        let generation = ConnectionGeneration()
        let removed = PINRemovingTransport()
        let channel = try makeChannel(base: removed, generation: generation)

        do {
            _ = try await channel.verify(password: Data("Public7!".utf8))
            XCTFail("Expected removal")
        } catch {
            XCTAssertEqual(error as? CardTransportError, .removed)
        }
        let removedLifecycle = await channel.snapshot()
        let removedSubmissions = await channel.submissionCount()
        XCTAssertEqual(removedLifecycle, .destroyed)
        XCTAssertEqual(removedSubmissions, 1)

        let peer = try PINPeer(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter,
            status: CardStatus(first: 0x90, second: 0x00)
        )
        let invalidated = try makeChannel(base: peer, generation: generation)
        await invalidated.invalidate(generation: ConnectionGeneration())
        let staleInvalidationLifecycle = await invalidated.snapshot()
        XCTAssertEqual(staleInvalidationLifecycle, .ready)
        await invalidated.invalidate(generation: generation)
        let exactInvalidationLifecycle = await invalidated.snapshot()
        XCTAssertEqual(exactInvalidationLifecycle, .destroyed)
    }

    private func makeChannel(
        base: any CardTransport,
        generation: ConnectionGeneration
    ) throws -> DNIePINSecureChannel {
        try DNIePINSecureChannel(
            base: base,
            generation: generation,
            channel: EphemeralChannelState(
                encryptionKey: encryptionKey,
                macKey: macKey,
                counter: counter
            )
        )
    }
}

private actor PINRemovingTransport: CardTransport {
    func transmit(
        _: CardTransportRequest,
        generation _: ConnectionGeneration,
        correlationID _: CorrelationID
    ) throws -> CardTransportResponse {
        throw CardTransportError.removed
    }
}

private actor PINPeer: CardTransport {
    private var state: EphemeralChannelState
    private let status: CardStatus
    private let tamperResponse: Bool
    private var input: Data?
    private var count = 0

    init(
        encryptionKey: Data,
        macKey: Data,
        counter: Data,
        status: CardStatus,
        tamperResponse: Bool = false
    ) throws {
        state = try EphemeralChannelState(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter
        )
        self.status = status
        self.tamperResponse = tamperResponse
    }

    func transmit(
        _ request: CardTransportRequest,
        generation _: ConnectionGeneration,
        correlationID _: CorrelationID
    ) throws -> CardTransportResponse {
        count += 1
        guard count == 1,
              request.kind == .verify,
              request.encodedCommand.count >= 5 else {
            throw CardTransportError.commandMismatch
        }
        let command = request.encodedCommand
        let objects = try SecureMessagingTLV.parseAll(Data(command.dropFirst(5)))
        guard command[0...3] == Data([0x0C, 0x20, 0x00, 0x00]),
              Int(command[4]) == command.count - 5,
              objects.map(\.tag) == [0x87, 0x8E],
              objects[0].value.first == 0x01 else {
            throw CardTransportError.commandMismatch
        }
        let commandCounter = try state.nextCounter()
        let commandMACInput = try CryptoPrimitives.iso7816Pad(
            try CryptoPrimitives.iso7816Pad(Data(command.prefix(4))) + objects[0].encoded
        )
        let authenticated = try state.withKeys { _, macKey in
            CryptoPrimitives.verifyTag(
                expected: try CryptoPrimitives.dnieMAC(
                    key: macKey,
                    incrementedCounter: commandCounter,
                    paddedMessage: commandMACInput
                ),
                actual: objects[1].value
            )
        }
        guard authenticated else { throw CardTransportError.commandMismatch }
        input = try state.withKeys { encryptionKey, _ in
            try CryptoPrimitives.dnieDecrypt(
                key: encryptionKey,
                incrementedCounter: commandCounter,
                ciphertext: Data(objects[0].value.dropFirst())
            )
        }

        let responseCounter = try state.nextCounter()
        let statusObject = SecureMessagingTLV.encode(
            tag: 0x99,
            value: Data([status.first, status.second])
        )
        var responseMAC = try state.withKeys { _, macKey in
            try CryptoPrimitives.dnieMAC(
                key: macKey,
                incrementedCounter: responseCounter,
                paddedMessage: CryptoPrimitives.iso7816Pad(statusObject)
            )
        }
        if tamperResponse { responseMAC[0] ^= 0x01 }
        return try CardTransportResponse(
            data: statusObject + SecureMessagingTLV.encode(tag: 0x8E, value: responseMAC),
            status: CardStatus(first: 0x90, second: 0x00),
            maximumLength: request.maximumResponseLength
        )
    }

    func observedInput() -> Data? { input }
    func requestCount() -> Int { count }
}

private func XCTAssertThrowsPINError<T>(
    _ expression: @autoclosure () async throws -> T,
    expected: PINSecureChannelError
) async {
    do {
        _ = try await expression()
        XCTFail("Expected PIN secure-channel error")
    } catch {
        XCTAssertEqual(error as? PINSecureChannelError, expected)
    }
}

private extension Data {
    init(pinHex: String) {
        self.init()
        var index = pinHex.startIndex
        while index < pinHex.endIndex {
            let next = pinHex.index(index, offsetBy: 2)
            append(UInt8(pinHex[index..<next], radix: 16)!)
            index = next
        }
    }
}
