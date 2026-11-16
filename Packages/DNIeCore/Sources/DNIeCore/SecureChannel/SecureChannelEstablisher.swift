import Foundation

public enum SecureChannelEstablishmentError: Error, Sendable, Equatable {
    case invalidResponse
    case invalidCertificate
    case invalidAuthentication
    case invalidSecureMessage
    case responseTooLarge
    case cardStatus(CardStatus)
    case invalidState
}

public actor DNIeSecureChannelEstablisher {
    private static let maximumFileLength = 8 * 1_024
    private static let maximumResponseLength = 8 * 1_024
    private static let maximumContinuationCount = 32
    private static let maximumReadLength = 255
    private static let algorithmReference = Data([0xFF, 0x44, 0x20, 0x4C])

    private let base: any CardTransport
    private let generation: ConnectionGeneration
    private let credentials: VerifiedCredentialSet
    private var wrappingState: EphemeralChannelState?
    private var operationInFlight = false

    public init(
        base: any CardTransport,
        generation: ConnectionGeneration,
        credentials: VerifiedCredentialSet
    ) {
        self.base = base
        self.generation = generation
        self.credentials = credentials
    }

    public func establishPINChannel() async throws -> DNIePINSecureChannel {
        try beginOperation()
        defer { operationInFlight = false }
        guard wrappingState == nil else {
            throw SecureChannelEstablishmentError.invalidState
        }
        let state = try await establish(role: .pin)
        return DNIePINSecureChannel(
            base: base,
            generation: generation,
            channel: state
        )
    }

    public func establishUserChannel() async throws -> DNIeUserSecureChannelTransport {
        try beginOperation()
        defer { operationInFlight = false }
        guard wrappingState == nil else {
            throw SecureChannelEstablishmentError.invalidState
        }
        let state = try await establish(role: .user)
        return DNIeUserSecureChannelTransport(
            base: base,
            generation: generation,
            channel: state
        )
    }

    public func establishUserChannel(
        from verifiedPINChannel: DNIePINSecureChannel
    ) async throws -> DNIeUserSecureChannelTransport {
        try beginOperation()
        defer { operationInFlight = false }
        guard wrappingState == nil else {
            throw SecureChannelEstablishmentError.invalidState
        }
        wrappingState = try await verifiedPINChannel.consumeVerifiedState()
        defer {
            if var wrappingState {
                wrappingState.destroy()
                self.wrappingState = nil
            }
        }
        let state = try await establish(role: .user)
        return DNIeUserSecureChannelTransport(
            base: base,
            generation: generation,
            channel: state
        )
    }

    private func beginOperation() throws {
        guard !operationInFlight else {
            throw SecureChannelEstablishmentError.invalidState
        }
        operationInFlight = true
    }

    private func establish(role: TerminalCredentialRole) async throws -> EphemeralChannelState {
        let chipInformation = try await exchange(
            kind: .getChipInformation,
            cla: 0x90,
            instruction: 0xB8,
            p1: 0,
            p2: 0,
            data: nil,
            expectedLength: 7
        )
        guard chipInformation.count == 7 else {
            throw SecureChannelEstablishmentError.invalidResponse
        }
        let cardSerial = Data([0]) + chipInformation

        let intermediateCertificate = try await readCertificate(fileIdentifier: 0x6020)
        let componentCertificate = try await readCertificate(fileIdentifier: 0x601F)
        let component: DNIeRSAPublicComponents
        do {
            component = try DNIeComponentCertificateChain.verify(
                intermediate: intermediateCertificate,
                component: componentCertificate,
                rootModulus: credentials.field(named: "icc_root_ca_modulus_1"),
                rootExponent: credentials.field(named: "icc_root_ca_public_exponent")
            )
        } catch {
            throw SecureChannelEstablishmentError.invalidCertificate
        }

        try await loadTerminalCertificates(role: role)
        let fields = try credentialFields(role: role)
        let terminalPrivate = try RawRSAKey(
            privatePKCS1: credentials.privateKeyPKCS1(role: role),
            modulus: fields.modulus,
            publicExponent: fields.exponent
        )
        let componentPublic = try RawRSAKey(
            publicModulus: component.modulus,
            publicExponent: component.exponent
        )

        var terminalRandom = try CryptoPrimitives.randomBytes(count: 8)
        defer { CryptoPrimitives.secureZero(&terminalRandom) }
        let internalResponse = try await exchange(
            kind: .internalAuthenticate,
            cla: 0,
            instruction: 0x88,
            p1: 0,
            p2: 0,
            data: terminalRandom + fields.serial,
            expectedLength: 128
        )
        guard internalResponse.count == 128 else {
            throw SecureChannelEstablishmentError.invalidAuthentication
        }
        var cardSeed: Data
        do {
            cardSeed = try DNIeAuthenticationBlock.recover(
                minimumSignature: terminalPrivate.privateOperation(internalResponse),
                signer: componentPublic,
                challenge: terminalRandom,
                serial: fields.serial
            )
        } catch {
            throw SecureChannelEstablishmentError.invalidAuthentication
        }
        defer { CryptoPrimitives.secureZero(&cardSeed) }

        var cardRandom = try await exchange(
            kind: .getChallenge,
            cla: 0,
            instruction: 0x84,
            p1: 0,
            p2: 0,
            data: nil,
            expectedLength: 8
        )
        guard cardRandom.count == 8 else {
            throw SecureChannelEstablishmentError.invalidResponse
        }
        defer { CryptoPrimitives.secureZero(&cardRandom) }
        var terminalSeed = try CryptoPrimitives.randomBytes(count: 32)
        defer { CryptoPrimitives.secureZero(&terminalSeed) }
        var externalBlock: Data
        do {
            externalBlock = try DNIeAuthenticationBlock.make(
                seed: terminalSeed,
                challenge: cardRandom,
                serial: cardSerial
            )
        } catch {
            throw SecureChannelEstablishmentError.invalidAuthentication
        }
        defer { CryptoPrimitives.secureZero(&externalBlock) }
        let terminalSignature = try terminalPrivate.privateOperation(externalBlock)
        let terminalMinimum = try FixedWidthUnsigned.minimumSignature(
            terminalSignature,
            modulus: fields.modulus
        )
        let externalRequest = try componentPublic.publicOperation(terminalMinimum)
        _ = try await exchange(
            kind: .externalAuthenticate,
            cla: 0,
            instruction: 0x82,
            p1: 0,
            p2: 0,
            data: externalRequest,
            expectedLength: nil
        )

        let keys = try CryptoPrimitives.deriveDNIeChannelKeys(
            terminalSeed: terminalSeed,
            cardSeed: cardSeed
        )
        var encryptionKey = keys.encryption
        var macKey = keys.mac
        defer {
            CryptoPrimitives.secureZero(&encryptionKey)
            CryptoPrimitives.secureZero(&macKey)
        }
        return try EphemeralChannelState(
            encryptionKey: encryptionKey,
            macKey: macKey,
            counter: cardRandom + terminalRandom
        )
    }

    private func credentialFields(role: TerminalCredentialRole) throws -> (
        modulus: Data,
        exponent: Data,
        serial: Data,
        certificate: Data,
        keyReference: Data
    ) {
        switch role {
        case .pin:
            return try (
                credentials.field(named: "ifd_pin_modulus_1"),
                credentials.field(named: "ifd_pin_public_exponent"),
                credentials.field(named: "sn_ifd_pin_1"),
                credentials.field(named: "C_CV_IFDUser_AUT_pin_cert_1"),
                credentials.field(named: "cvc_ifd_keyref_pin_1")
            )
        case .user:
            return try (
                credentials.field(named: "ifd_modulus_1"),
                credentials.field(named: "ifd_public_exponent"),
                credentials.field(named: "sn_ifd_1"),
                credentials.field(named: "C_CV_IFDUser_AUT_cert_1"),
                credentials.field(named: "cvc_ifd_keyref_1")
            )
        }
    }

    private func loadTerminalCertificates(role: TerminalCredentialRole) async throws {
        let fields = try credentialFields(role: role)
        _ = try await exchange(
            kind: .manageSecurityEnvironment,
            cla: 0,
            instruction: 0x22,
            p1: 0x81,
            p2: 0xB6,
            data: SecureMessagingTLV.encode(
                tag: 0x83,
                value: credentials.field(named: "root_ca_keyref")
            ),
            expectedLength: nil
        )
        _ = try await exchange(
            kind: .externalAuthenticate,
            cla: 0,
            instruction: 0x2A,
            p1: 0,
            p2: 0xAE,
            data: credentials.field(named: "C_CV_CA_CS_AUT_cert_1"),
            expectedLength: nil
        )
        _ = try await exchange(
            kind: .manageSecurityEnvironment,
            cla: 0,
            instruction: 0x22,
            p1: 0x81,
            p2: 0xB6,
            data: SecureMessagingTLV.encode(
                tag: 0x83,
                value: credentials.field(named: "cvc_intca_keyref_1")
            ),
            expectedLength: nil
        )
        _ = try await exchange(
            kind: .externalAuthenticate,
            cla: 0,
            instruction: 0x2A,
            p1: 0,
            p2: 0xAE,
            data: fields.certificate,
            expectedLength: nil
        )
        var environment = SecureMessagingTLV.encode(
            tag: 0x83,
            value: fields.keyReference
        )
        environment.append(SecureMessagingTLV.encode(
            tag: 0x84,
            value: try credentials.field(named: "icc_priv_keyref")
        ))
        environment.append(SecureMessagingTLV.encode(
            tag: 0x80,
            value: Self.algorithmReference
        ))
        _ = try await exchange(
            kind: .manageSecurityEnvironment,
            cla: 0,
            instruction: 0x22,
            p1: 0xC1,
            p2: 0xA4,
            data: environment,
            expectedLength: nil
        )
    }

    private func readCertificate(fileIdentifier: UInt16) async throws -> Data {
        _ = try await selectFile(0x3F00)
        let fci = try await selectFile(fileIdentifier)
        let allocation = try fileLength(from: fci)
        var output = Data()
        output.reserveCapacity(allocation)
        while output.count < allocation {
            let offset = output.count
            let length = min(Self.maximumReadLength, allocation - offset)
            let chunk = try await exchange(
                kind: .readBinary,
                cla: 0,
                instruction: 0xB0,
                p1: UInt8((offset >> 8) & 0x7F),
                p2: UInt8(offset & 0xFF),
                data: nil,
                expectedLength: length
            )
            guard chunk.count == length else {
                throw SecureChannelEstablishmentError.invalidCertificate
            }
            output.append(chunk)
        }
        let first = try SecureMessagingTLV.parsePrefix(output)
        guard first.tag == 0x30,
              output[first.encoded.count...].allSatisfy({ $0 == 0 || $0 == 0xFF }) else {
            throw SecureChannelEstablishmentError.invalidCertificate
        }
        return first.encoded
    }

    private func selectFile(_ identifier: UInt16) async throws -> Data {
        try await exchange(
            kind: .select,
            cla: 0,
            instruction: 0xA4,
            p1: 0,
            p2: 0,
            data: Data([UInt8(identifier >> 8), UInt8(identifier & 0xFF)]),
            expectedLength: 0
        )
    }

    private func exchange(
        kind: CardTransportCommandKind,
        cla: UInt8,
        instruction: UInt8,
        p1: UInt8,
        p2: UInt8,
        data: Data?,
        expectedLength: Int?
    ) async throws -> Data {
        var result = try await sendOnce(
            kind: kind,
            cla: cla,
            instruction: instruction,
            p1: p1,
            p2: p2,
            data: data,
            expectedLength: expectedLength
        )
        if result.status.first == 0x6C {
            result = try await sendOnce(
                kind: kind,
                cla: cla,
                instruction: instruction,
                p1: p1,
                p2: p2,
                data: data,
                expectedLength: result.status.second == 0 ? 256 : Int(result.status.second)
            )
        }
        var response = result.data
        var continuationCount = 0
        while wrappingState == nil, result.status.first == 0x61 {
            guard continuationCount < Self.maximumContinuationCount else {
                throw SecureChannelEstablishmentError.responseTooLarge
            }
            result = try await sendOnce(
                kind: .getResponse,
                cla: 0,
                instruction: 0xC0,
                p1: 0,
                p2: 0,
                data: nil,
                expectedLength: result.status.second == 0 ? 256 : Int(result.status.second)
            )
            guard response.count + result.data.count <= Self.maximumResponseLength else {
                throw SecureChannelEstablishmentError.responseTooLarge
            }
            response.append(result.data)
            continuationCount += 1
        }
        guard result.status == CardStatus(first: 0x90, second: 0x00) else {
            throw SecureChannelEstablishmentError.cardStatus(result.status)
        }
        return response
    }

    private func sendOnce(
        kind: CardTransportCommandKind,
        cla: UInt8,
        instruction: UInt8,
        p1: UInt8,
        p2: UInt8,
        data: Data?,
        expectedLength: Int?
    ) async throws -> CardTransportResponse {
        if wrappingState != nil {
            return try await sendProtected(
                kind: kind,
                cla: cla,
                instruction: instruction,
                p1: p1,
                p2: p2,
                data: data,
                expectedLength: expectedLength
            )
        }
        return try await base.transmit(
            CardTransportRequest(
                kind: kind,
                structuredCommand: CardStructuredCommand(
                    cla: cla,
                    instruction: instruction,
                    p1: p1,
                    p2: p2,
                    data: data,
                    expectedResponseLength: expectedLength
                ),
                maximumResponseLength: expectedLength.flatMap {
                    $0 > 0 ? $0 : nil
                } ?? Self.maximumResponseLength
            ),
            generation: generation,
            correlationID: CorrelationID()
        )
    }

    private func sendProtected(
        kind: CardTransportCommandKind,
        cla: UInt8,
        instruction: UInt8,
        p1: UInt8,
        p2: UInt8,
        data: Data?,
        expectedLength: Int?
    ) async throws -> CardTransportResponse {
        guard var state = wrappingState else {
            throw SecureChannelEstablishmentError.invalidState
        }
        defer { wrappingState = state }
        let commandCounter = try state.nextCounter()
        var authenticatedObjects = Data()
        if let data, !data.isEmpty {
            let encrypted = try state.withKeys { encryptionKey, _ in
                try CryptoPrimitives.dnieEncrypt(
                    key: encryptionKey,
                    incrementedCounter: commandCounter,
                    plaintext: data
                )
            }
            authenticatedObjects.append(SecureMessagingTLV.encode(
                tag: 0x87,
                value: Data([0x01]) + encrypted
            ))
        } else if let expectedLength, expectedLength > 0 {
            guard expectedLength <= 256 else {
                throw SecureChannelEstablishmentError.responseTooLarge
            }
            authenticatedObjects.append(SecureMessagingTLV.encode(
                tag: 0x97,
                value: Data([expectedLength == 256 ? 0 : UInt8(expectedLength)])
            ))
        }
        let protectedCLA = cla | 0x0C
        let paddedHeader = try CryptoPrimitives.iso7816Pad(Data([
            protectedCLA, instruction, p1, p2,
        ]))
        let macInput = try CryptoPrimitives.iso7816Pad(
            paddedHeader + authenticatedObjects
        )
        let mac = try state.withKeys { _, macKey in
            try CryptoPrimitives.dnieMAC(
                key: macKey,
                incrementedCounter: commandCounter,
                paddedMessage: macInput
            )
        }
        let body = authenticatedObjects + SecureMessagingTLV.encode(tag: 0x8E, value: mac)
        guard body.count <= UInt8.max else {
            throw SecureChannelEstablishmentError.responseTooLarge
        }
        var outer = try await base.transmit(
            CardTransportRequest(
                kind: kind,
                encodedCommand: Data([
                    protectedCLA, instruction, p1, p2, UInt8(body.count),
                ]) + body,
                maximumResponseLength: Self.maximumResponseLength
            ),
            generation: generation,
            correlationID: CorrelationID()
        )
        var protectedResponse = outer.data
        var continuationCount = 0
        while outer.status.first == 0x61 {
            guard continuationCount < Self.maximumContinuationCount else {
                throw SecureChannelEstablishmentError.responseTooLarge
            }
            outer = try await base.transmit(
                CardTransportRequest(
                    kind: .getResponse,
                    encodedCommand: Data([0, 0xC0, 0, 0, outer.status.second]),
                    maximumResponseLength: Self.maximumResponseLength
                ),
                generation: generation,
                correlationID: CorrelationID()
            )
            protectedResponse.append(outer.data)
            guard protectedResponse.count <= Self.maximumResponseLength else {
                throw SecureChannelEstablishmentError.responseTooLarge
            }
            continuationCount += 1
        }
        guard outer.status == CardStatus(first: 0x90, second: 0x00) else {
            throw SecureChannelEstablishmentError.cardStatus(outer.status)
        }
        let responseCounter = try state.nextCounter()
        let objects = try SecureMessagingTLV.parseAll(protectedResponse)
        guard objects.map(\.tag) == [0x99, 0x8E]
                || objects.map(\.tag) == [0x87, 0x99, 0x8E],
              let statusObject = objects.first(where: { $0.tag == 0x99 }),
              statusObject.value.count == 2,
              let macObject = objects.last,
              macObject.value.count == 8 else {
            throw SecureChannelEstablishmentError.invalidSecureMessage
        }
        let responseMACInput = try CryptoPrimitives.iso7816Pad(
            objects.dropLast().reduce(into: Data()) { $0.append($1.encoded) }
        )
        let accepted = try state.withKeys { _, macKey in
            CryptoPrimitives.verifyTag(
                expected: try CryptoPrimitives.dnieMAC(
                    key: macKey,
                    incrementedCounter: responseCounter,
                    paddedMessage: responseMACInput
                ),
                actual: macObject.value
            )
        }
        guard accepted else {
            throw SecureChannelEstablishmentError.invalidSecureMessage
        }
        let status = CardStatus(
            first: statusObject.value[0],
            second: statusObject.value[1]
        )
        var plaintext = Data()
        if let encrypted = objects.first(where: { $0.tag == 0x87 }) {
            guard encrypted.value.first == 0x01 else {
                throw SecureChannelEstablishmentError.invalidSecureMessage
            }
            plaintext = try state.withKeys { encryptionKey, _ in
                try CryptoPrimitives.dnieDecrypt(
                    key: encryptionKey,
                    incrementedCounter: responseCounter,
                    ciphertext: Data(encrypted.value.dropFirst())
                )
            }
        }
        return try CardTransportResponse(
            data: plaintext,
            status: status,
            maximumLength: expectedLength.flatMap {
                $0 > 0 ? $0 : nil
            } ?? Self.maximumResponseLength
        )
    }

    private func fileLength(from fci: Data) throws -> Int {
        guard let value = findTLV(tag: 0x85, in: fci, depth: 4), value.count >= 5 else {
            throw SecureChannelEstablishmentError.invalidCertificate
        }
        let length = Int(value[3]) << 8 | Int(value[4])
        guard (1...Self.maximumFileLength).contains(length) else {
            throw SecureChannelEstablishmentError.invalidCertificate
        }
        return length
    }

    private func findTLV(tag: Int, in data: Data, depth: Int) -> Data? {
        guard depth > 0, let items = try? SecureMessagingTLV.parseAll(data) else {
            return nil
        }
        for item in items {
            if item.tag == tag { return item.value }
            if item.tag & 0x20 != 0,
               let nested = findTLV(tag: tag, in: item.value, depth: depth - 1) {
                return nested
            }
        }
        return nil
    }
}
