import Foundation
import XCTest
@testable import DNIeCore

final class UserSecureChannelTransportTests: XCTestCase {
    private let encryptionKey = Data(hex: "7252e29d5ab69ed89924263128e7e997")
    private let macKey = Data(hex: "e7fa91b49f6e83703a0f9c63708bcd6d")
    private let counter = Data(hex: "44ced6da57b5ae2af1f13263f6a104d9")

    func testSigningCrossesAuthenticatedSecureMessagingWithSynchronizedCounters() async throws {
        let signature = Data((0..<256).map { UInt8($0 & 0xFF) })
        let generation = ConnectionGeneration()
        let peer = try SecureMessagingPeer(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter,
            signature: signature
        )
        let channel = try makeChannel(base: peer, generation: generation)
        let digest = Data(repeating: 0x5A, count: 32)

        let result = try await DNIeSigning.signSHA256Digest(
            digest,
            keyReference: 0x01,
            protectedTransport: channel,
            generation: generation
        )

        XCTAssertEqual(result, signature)
        let plaintextCommands = await peer.plaintextCommands()
        XCTAssertEqual(plaintextCommands, [
            Data([0x84, 0x02, 0x01, 0x01]),
            DNIeSigning.sha256DigestInfoPrefix + digest,
        ])
        let state = await channel.snapshot()
        XCTAssertEqual(state, .active)
    }

    func testRepeatedSigningKeepsCountersSynchronizedAndReportsBothStages() async throws {
        let signature = Data((0..<256).map { UInt8($0 & 0xFF) })
        let generation = ConnectionGeneration()
        let peer = try SecureMessagingPeer(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter,
            signature: signature
        )
        let channel = try makeChannel(base: peer, generation: generation)
        let stages = StageRecorder()

        for byte in [UInt8(0x5A), UInt8(0xA5)] {
            let result = try await DNIeSigning.signSHA256Digest(
                Data(repeating: byte, count: 32),
                keyReference: 0x01,
                protectedTransport: channel,
                generation: generation,
                stageCompleted: { stage in stages.append(stage) }
            )
            XCTAssertEqual(result, signature)
        }

        let plaintextCommands = await peer.plaintextCommands()
        XCTAssertEqual(plaintextCommands.count, 4)
        XCTAssertEqual(stages.snapshot(), [
            .manageSecurityEnvironment,
            .computeDigitalSignature,
            .manageSecurityEnvironment,
            .computeDigitalSignature,
        ])
        let state = await channel.snapshot()
        XCTAssertEqual(state, .active)
    }

    func testPSOResponseShapeFailuresRemainClosedAndCategorical() async throws {
        let generation = ConnectionGeneration()
        let cases: [(Data, SecureChannelResponseFailure)] = [
            (Data(), .empty),
            (Data([0x87, 0x83]) + Data(repeating: 0, count: 254), .malformedTLVAtExactDataLength),
            (
                Data([0x99, 0x02, 0x90, 0x00, 0x87, 0x01, 0x01, 0x8E, 0x08])
                    + Data(repeating: 0, count: 8),
                .objectSequence
            ),
        ]

        for (response, expectedFailure) in cases {
            let fixed = FixedResponseTransport(data: response)
            let channel = try makeChannel(base: fixed, generation: generation)
            do {
                _ = try await channel.transmit(
                    psoRequest(),
                    generation: generation,
                    correlationID: CorrelationID()
                )
                XCTFail("Expected closed response-shape failure")
            } catch {
                XCTAssertEqual(
                    error as? SecureChannelTransportError,
                    .invalidResponse(expectedFailure)
                )
            }
            let state = await channel.snapshot()
            XCTAssertEqual(state, .destroyed)
        }
    }

    func testAuthenticatedStatusOnlyPSOErrorSurfacesInnerStatus() async throws {
        let generation = ConnectionGeneration()
        let status = CardStatus(first: 0x69, second: 0x82)
        let fixed = FixedResponseTransport(data: try statusOnlyResponse(status: status))
        let channel = try makeChannel(base: fixed, generation: generation)

        do {
            _ = try await channel.transmit(
                psoRequest(),
                generation: generation,
                correlationID: CorrelationID()
            )
            XCTFail("Expected authenticated inner status")
        } catch {
            XCTAssertEqual(error as? SecureChannelTransportError, .innerStatus(status))
        }
        let state = await channel.snapshot()
        XCTAssertEqual(state, .destroyed)
    }

    func testTamperedStatusOnlyPSOErrorFailsAuthenticationBeforeStatus() async throws {
        let generation = ConnectionGeneration()
        var response = try statusOnlyResponse(status: CardStatus(first: 0x69, second: 0x82))
        response[response.index(before: response.endIndex)] ^= 0x01
        let fixed = FixedResponseTransport(data: response)
        let channel = try makeChannel(base: fixed, generation: generation)

        do {
            _ = try await channel.transmit(
                psoRequest(),
                generation: generation,
                correlationID: CorrelationID()
            )
            XCTFail("Expected authentication failure")
        } catch {
            XCTAssertEqual(error as? SecureChannelTransportError, .invalidAuthentication)
        }
        let state = await channel.snapshot()
        XCTAssertEqual(state, .destroyed)
    }

    func testAuthenticatedStatusOnlyPSOSuccessFailsWithoutSignatureData() async throws {
        let generation = ConnectionGeneration()
        let fixed = FixedResponseTransport(
            data: try statusOnlyResponse(status: CardStatus(first: 0x90, second: 0x00))
        )
        let channel = try makeChannel(base: fixed, generation: generation)

        do {
            _ = try await channel.transmit(
                psoRequest(),
                generation: generation,
                correlationID: CorrelationID()
            )
            XCTFail("Expected missing signature data failure")
        } catch {
            XCTAssertEqual(
                error as? SecureChannelTransportError,
                .invalidResponse(.missingEncryptedDataOnSuccess)
            )
        }
        let state = await channel.snapshot()
        XCTAssertEqual(state, .destroyed)
    }

    func testTamperedResponseDestroysChannelAndNoSecondCommandCanRun() async throws {
        let generation = ConnectionGeneration()
        let peer = try SecureMessagingPeer(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter,
            signature: Data(repeating: 0, count: 256),
            tamperFirstResponse: true
        )
        let channel = try makeChannel(base: peer, generation: generation)
        let request = try mseRequest()

        do {
            _ = try await channel.transmit(
                request,
                generation: generation,
                correlationID: CorrelationID()
            )
            XCTFail("Expected authentication failure")
        } catch {
            XCTAssertEqual(error as? SecureChannelTransportError, .invalidAuthentication)
        }
        let destroyedAfterTamper = await channel.snapshot()
        XCTAssertEqual(destroyedAfterTamper, .destroyed)

        do {
            _ = try await channel.transmit(
                request,
                generation: generation,
                correlationID: CorrelationID()
            )
            XCTFail("Destroyed channel was reused")
        } catch {
            XCTAssertEqual(error as? SecureChannelTransportError, .destroyedState)
        }
        let requestCountAfterTamper = await peer.requestCount()
        XCTAssertEqual(requestCountAfterTamper, 1)
    }

    func testRemovalDestroysChannelAndStaleGenerationNeverReachesTransport() async throws {
        let generation = ConnectionGeneration()
        let removed = RemovingTransport()
        let channel = try makeChannel(base: removed, generation: generation)
        let request = try mseRequest()

        do {
            _ = try await channel.transmit(
                request,
                generation: ConnectionGeneration(),
                correlationID: CorrelationID()
            )
            XCTFail("Expected stale generation")
        } catch {
            XCTAssertEqual(error as? CardTransportError, .staleGeneration)
        }
        let requestsBeforeRemoval = await removed.requestCount()
        let stateBeforeRemoval = await channel.snapshot()
        XCTAssertEqual(requestsBeforeRemoval, 0)
        XCTAssertEqual(stateBeforeRemoval, .active)

        do {
            _ = try await channel.transmit(
                request,
                generation: generation,
                correlationID: CorrelationID()
            )
            XCTFail("Expected removal")
        } catch {
            XCTAssertEqual(error as? CardTransportError, .removed)
        }
        let stateAfterRemoval = await channel.snapshot()
        let requestsAfterRemoval = await removed.requestCount()
        XCTAssertEqual(stateAfterRemoval, .destroyed)
        XCTAssertEqual(requestsAfterRemoval, 1)
    }

    func testExplicitInvalidationClearsOnlyTheMatchingGeneration() async throws {
        let generation = ConnectionGeneration()
        let peer = try SecureMessagingPeer(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter,
            signature: Data(repeating: 0, count: 256)
        )
        let channel = try makeChannel(base: peer, generation: generation)

        await channel.invalidate(generation: ConnectionGeneration())
        let stateAfterStaleInvalidation = await channel.snapshot()
        XCTAssertEqual(stateAfterStaleInvalidation, .active)
        await channel.invalidate(generation: generation)
        let stateAfterExactInvalidation = await channel.snapshot()
        XCTAssertEqual(stateAfterExactInvalidation, .destroyed)
    }

    private func makeChannel(
        base: any CardTransport,
        generation: ConnectionGeneration
    ) throws -> DNIeUserSecureChannelTransport {
        try DNIeUserSecureChannelTransport(
            base: base,
            generation: generation,
            channel: EphemeralChannelState(
                encryptionKey: encryptionKey,
                macKey: macKey,
                counter: counter
            )
        )
    }

    private func mseRequest() throws -> CardTransportRequest {
        try CardTransportRequest(
            kind: .manageSecurityEnvironment,
            structuredCommand: CardStructuredCommand(
                cla: 0x00,
                instruction: 0x22,
                p1: 0x41,
                p2: 0xB6,
                data: Data([0x84, 0x02, 0x01, 0x01])
            ),
            maximumResponseLength: 0
        )
    }

    private func psoRequest() throws -> CardTransportRequest {
        try CardTransportRequest(
            kind: .computeDigitalSignature,
            structuredCommand: CardStructuredCommand(
                cla: 0x00,
                instruction: 0x2A,
                p1: 0x9E,
                p2: 0x9A,
                data: DNIeSigning.sha256DigestInfoPrefix + Data(repeating: 0, count: 32),
                expectedResponseLength: 256
            ),
            maximumResponseLength: 256
        )
    }

    private func statusOnlyResponse(status: CardStatus) throws -> Data {
        var peerState = try EphemeralChannelState(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter
        )
        _ = try peerState.nextCounter()
        let responseCounter = try peerState.nextCounter()
        let statusObject = SecureMessagingTLV.encode(
            tag: 0x99,
            value: Data([status.first, status.second])
        )
        let macInput = try CryptoPrimitives.iso7816Pad(statusObject)
        let mac = try peerState.withKeys { _, macKey in
            try CryptoPrimitives.dnieMAC(
                key: macKey,
                incrementedCounter: responseCounter,
                paddedMessage: macInput
            )
        }
        return statusObject + SecureMessagingTLV.encode(tag: 0x8E, value: mac)
    }
}

private actor FixedResponseTransport: CardTransport {
    private let data: Data

    init(data: Data) {
        self.data = data
    }

    func transmit(
        _ request: CardTransportRequest,
        generation _: ConnectionGeneration,
        correlationID _: CorrelationID
    ) throws -> CardTransportResponse {
        try CardTransportResponse(
            data: data,
            status: CardStatus(first: 0x90, second: 0x00),
            maximumLength: request.maximumResponseLength
        )
    }
}

private actor RemovingTransport: CardTransport {
    private var count = 0

    func transmit(
        _: CardTransportRequest,
        generation _: ConnectionGeneration,
        correlationID _: CorrelationID
    ) throws -> CardTransportResponse {
        count += 1
        throw CardTransportError.removed
    }

    func requestCount() -> Int { count }
}

private actor SecureMessagingPeer: CardTransport {
    private var state: EphemeralChannelState
    private let signature: Data
    private let tamperFirstResponse: Bool
    private var plaintext: [Data] = []
    private var count = 0

    init(
        encryptionKey: Data,
        macKey: Data,
        counter: Data,
        signature: Data,
        tamperFirstResponse: Bool = false
    ) throws {
        state = try EphemeralChannelState(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: counter
        )
        self.signature = signature
        self.tamperFirstResponse = tamperFirstResponse
    }

    func transmit(
        _ request: CardTransportRequest,
        generation _: ConnectionGeneration,
        correlationID _: CorrelationID
    ) throws -> CardTransportResponse {
        count += 1
        guard request.kind != .getResponse else {
            throw CardTransportError.commandMismatch
        }
        let command = request.encodedCommand
        guard command.count >= 5,
              command[0] == 0x0C,
              Int(command[4]) == command.count - 5 else {
            throw CardTransportError.commandMismatch
        }
        let objects = try SecureMessagingTLV.parseAll(Data(command.dropFirst(5)))
        guard objects.map(\.tag) == [0x87, 0x8E],
              objects[0].value.first == 0x01,
              objects[1].value.count == 8 else {
            throw CardTransportError.commandMismatch
        }
        let commandCounter = try state.nextCounter()
        let macInput = try CryptoPrimitives.iso7816Pad(
            try CryptoPrimitives.iso7816Pad(Data(command.prefix(4))) + objects[0].encoded
        )
        let authenticated = try state.withKeys { _, macKey in
            CryptoPrimitives.verifyTag(
                expected: try CryptoPrimitives.dnieMAC(
                    key: macKey,
                    incrementedCounter: commandCounter,
                    paddedMessage: macInput
                ),
                actual: objects[1].value
            )
        }
        guard authenticated else { throw CardTransportError.commandMismatch }
        let decoded = try state.withKeys { encryptionKey, _ in
            try CryptoPrimitives.dnieDecrypt(
                key: encryptionKey,
                incrementedCounter: commandCounter,
                ciphertext: Data(objects[0].value.dropFirst())
            )
        }
        plaintext.append(decoded)

        let responseCounter = try state.nextCounter()
        var responseObjects = Data()
        if count.isMultiple(of: 2) {
            let ciphertext = try state.withKeys { encryptionKey, _ in
                try CryptoPrimitives.dnieEncrypt(
                    key: encryptionKey,
                    incrementedCounter: responseCounter,
                    plaintext: signature
                )
            }
            responseObjects.append(SecureMessagingTLV.encode(
                tag: 0x87,
                value: Data([0x01]) + ciphertext
            ))
        }
        responseObjects.append(SecureMessagingTLV.encode(
            tag: 0x99,
            value: Data([0x90, 0x00])
        ))
        let responseMACInput = try CryptoPrimitives.iso7816Pad(responseObjects)
        var responseMAC = try state.withKeys { _, macKey in
            try CryptoPrimitives.dnieMAC(
                key: macKey,
                incrementedCounter: responseCounter,
                paddedMessage: responseMACInput
            )
        }
        if tamperFirstResponse, count == 1 { responseMAC[0] ^= 0x01 }
        responseObjects.append(SecureMessagingTLV.encode(tag: 0x8E, value: responseMAC))
        return try CardTransportResponse(
            data: responseObjects,
            status: CardStatus(first: 0x90, second: 0x00),
            maximumLength: request.maximumResponseLength
        )
    }

    func plaintextCommands() -> [Data] { plaintext }
    func requestCount() -> Int { count }
}

private final class StageRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var stages: [DNIeSigningStage] = []

    func append(_ stage: DNIeSigningStage) {
        lock.lock()
        stages.append(stage)
        lock.unlock()
    }

    func snapshot() -> [DNIeSigningStage] {
        lock.lock()
        defer { lock.unlock() }
        return stages
    }
}

private extension Data {
    init(hex: String) {
        self.init()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
    }
}
