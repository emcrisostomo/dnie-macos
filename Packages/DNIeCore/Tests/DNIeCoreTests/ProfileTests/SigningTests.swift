import DNIeCore
import Foundation
import Security
import XCTest

final class SigningTests: XCTestCase {
    func testExactAuthenticationSignatureUsesOnlyTheCardTransportAndVerifies() async throws {
        let digest = CryptoPrimitives.sha256(Data("production signing boundary".utf8))
        let privateKey = try makeTestPrivateKey()
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        var signingError: Unmanaged<CFError>?
        let signature = try XCTUnwrap(SecKeyCreateSignature(
            privateKey,
            .rsaSignatureDigestPKCS1v15SHA256,
            digest as CFData,
            &signingError
        ) as Data?)
        XCTAssertNil(signingError)

        let transport = SigningCardTransport(signature: signature)
        let generation = ConnectionGeneration()
        let result = try await DNIeSigning.signSHA256Digest(
            digest,
            keyReference: 0x01,
            protectedTransport: transport,
            generation: generation
        )

        var verificationError: Unmanaged<CFError>?
        XCTAssertTrue(SecKeyVerifySignature(
            publicKey,
            .rsaSignatureDigestPKCS1v15SHA256,
            digest as CFData,
            result as CFData,
            &verificationError
        ))
        XCTAssertNil(verificationError)

        let requests = await transport.requests()
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests[0].kind, .manageSecurityEnvironment)
        XCTAssertEqual(requests[0].structuredCommand, try CardStructuredCommand(
            cla: 0x00,
            instruction: 0x22,
            p1: 0x41,
            p2: 0xB6,
            data: Data([0x84, 0x02, 0x01, 0x01])
        ))
        XCTAssertEqual(requests[1].kind, .computeDigitalSignature)
        XCTAssertEqual(requests[1].structuredCommand, try CardStructuredCommand(
            cla: 0x00,
            instruction: 0x2A,
            p1: 0x9E,
            p2: 0x9A,
            data: DNIeSigning.sha256DigestInfoPrefix + digest,
            expectedResponseLength: 256
        ))
    }

    func testUnsupportedInputFailsBeforeCardTransport() async throws {
        for (digest, keyReference) in [
            (Data(repeating: 0, count: 31), UInt8(0x01)),
            (Data(repeating: 0, count: 33), UInt8(0x01)),
            (Data(repeating: 0, count: 32), UInt8(0x02)),
        ] {
            let transport = SigningCardTransport(signature: Data(repeating: 0, count: 256))

            do {
                _ = try await DNIeSigning.signSHA256Digest(
                    digest,
                    keyReference: keyReference,
                    protectedTransport: transport,
                    generation: ConnectionGeneration()
                )
                XCTFail("Expected exact-boundary rejection")
            } catch {
                XCTAssertEqual(error as? DNIeSigningError, .unsupportedOperation)
            }
            let requestCount = await transport.requestCount()
            XCTAssertEqual(requestCount, 0)
        }
    }

    func testUnexpectedStatusAndMalformedSignatureFailClosedWithoutRetry() async throws {
        let digest = Data(repeating: 0xA5, count: 32)
        for scenario in [
            SigningCardTransport.Scenario.mseStatus(CardStatus(first: 0x69, second: 0x82)),
            .psoStatus(CardStatus(first: 0x6F, second: 0x00)),
            .signature(Data(repeating: 0, count: 255)),
        ] {
            let transport = SigningCardTransport(scenario: scenario)

            do {
                _ = try await DNIeSigning.signSHA256Digest(
                    digest,
                    keyReference: 0x01,
                    protectedTransport: transport,
                    generation: ConnectionGeneration()
                )
                XCTFail("Expected fail-closed result")
            } catch {
                XCTAssertEqual(error as? DNIeSigningError, .invalidCardResponse)
            }
            let requestCount = await transport.requestCount()
            XCTAssertLessThanOrEqual(requestCount, 2)
        }
    }

    private func makeTestPrivateKey() throws -> SecKey {
        var error: Unmanaged<CFError>?
        let key = SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ] as CFDictionary, &error)
        if let error { throw error.takeRetainedValue() }
        return try XCTUnwrap(key)
    }
}

private actor SigningCardTransport: UserSecureCardTransport {
    enum Scenario: Sendable {
        case signature(Data)
        case mseStatus(CardStatus)
        case psoStatus(CardStatus)
    }

    private let scenario: Scenario
    private var recordedRequests: [CardTransportRequest] = []

    init(signature: Data) {
        scenario = .signature(signature)
    }

    init(scenario: Scenario) {
        self.scenario = scenario
    }

    func transmit(
        _ request: CardTransportRequest,
        generation _: ConnectionGeneration,
        correlationID _: CorrelationID
    ) throws -> CardTransportResponse {
        recordedRequests.append(request)
        switch (recordedRequests.count, scenario) {
        case (1, let .mseStatus(status)):
            return try CardTransportResponse(data: Data(), status: status, maximumLength: 0)
        case (1, _):
            return try CardTransportResponse(
                data: Data(),
                status: CardStatus(first: 0x90, second: 0x00),
                maximumLength: 0
            )
        case (2, let .signature(signature)):
            return try CardTransportResponse(
                data: signature,
                status: CardStatus(first: 0x90, second: 0x00),
                maximumLength: 256
            )
        case (2, let .psoStatus(status)):
            return try CardTransportResponse(data: Data(), status: status, maximumLength: 256)
        default:
            throw CardTransportError.commandMismatch
        }
    }

    func requests() -> [CardTransportRequest] {
        recordedRequests
    }

    func requestCount() -> Int {
        recordedRequests.count
    }
}
