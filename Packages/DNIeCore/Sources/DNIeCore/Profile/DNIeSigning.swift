import Foundation

public enum DNIeSigningError: Error, Sendable, Equatable {
    case unsupportedOperation
    case invalidCardResponse
}

public enum DNIeSigningStage: String, Sendable, Equatable {
    case manageSecurityEnvironment
    case computeDigitalSignature
}

public enum DNIeSigning {
    public static let sha256DigestInfoPrefix = Data([
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ])

    public static func signSHA256Digest(
        _ digest: Data,
        keyReference: UInt8,
        protectedTransport: any UserSecureCardTransport,
        generation: ConnectionGeneration,
        stageCompleted: (@Sendable (DNIeSigningStage) -> Void)? = nil
    ) async throws -> Data {
        guard digest.count == 32, keyReference == 0x01 else {
            throw DNIeSigningError.unsupportedOperation
        }

        let correlationID = CorrelationID()
        let selection = try CardTransportRequest(
            kind: .manageSecurityEnvironment,
            structuredCommand: CardStructuredCommand(
                cla: 0x00,
                instruction: 0x22,
                p1: 0x41,
                p2: 0xB6,
                data: Data([0x84, 0x02, 0x01, keyReference])
            ),
            maximumResponseLength: 0
        )
        let selectionResponse = try await protectedTransport.transmit(
            selection,
            generation: generation,
            correlationID: correlationID
        )
        guard selectionResponse.status == CardStatus(first: 0x90, second: 0x00),
              selectionResponse.data.isEmpty else {
            throw DNIeSigningError.invalidCardResponse
        }
        stageCompleted?(.manageSecurityEnvironment)

        var digestInfo = sha256DigestInfoPrefix
        digestInfo.append(digest)
        defer { CryptoPrimitives.secureZero(&digestInfo) }
        let signatureRequest = try CardTransportRequest(
            kind: .computeDigitalSignature,
            structuredCommand: CardStructuredCommand(
                cla: 0x00,
                instruction: 0x2A,
                p1: 0x9E,
                p2: 0x9A,
                data: digestInfo,
                expectedResponseLength: 256
            ),
            maximumResponseLength: 256
        )
        let signatureResponse = try await protectedTransport.transmit(
            signatureRequest,
            generation: generation,
            correlationID: correlationID
        )
        guard signatureResponse.status == CardStatus(first: 0x90, second: 0x00),
              signatureResponse.data.count == 256 else {
            throw DNIeSigningError.invalidCardResponse
        }
        stageCompleted?(.computeDigitalSignature)
        return signatureResponse.data
    }
}
