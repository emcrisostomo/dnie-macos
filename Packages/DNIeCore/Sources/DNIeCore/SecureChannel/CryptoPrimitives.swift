import CommonCrypto
import Darwin
import Foundation
import Security

public enum CryptoPrimitiveError: Error, Equatable, Sendable {
    case invalidAESKeyLength
    case invalidBlockLength
    case invalidIVLength
    case inputTooLarge
    case counterOverflow
    case invalidPadding
    case commonCryptoFailure(Int32)
    case securityFailure(Int32)
    case invalidRSAKey
    case invalidRSAValue
    case destroyedState
}

/// The reviewed system-primitive boundary selected by ADR-008.
///
/// AES, hashes, and randomness are supplied by macOS. This type owns only the
/// bounded RFC 4493 CMAC composition and the evidence-backed DNIe transforms.
public enum CryptoPrimitives {
    public static let aesBlockSize = kCCBlockSizeAES128
    public static let maximumCMACInput = 1_048_576

    public static func sha256(_ data: Data) -> Data {
        var digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { input in
            digest.withUnsafeMutableBytes { output in
                _ = CC_SHA256(
                    input.baseAddress,
                    CC_LONG(input.count),
                    output.bindMemory(to: UInt8.self).baseAddress
                )
            }
        }
        return digest
    }

    public static func sha1(_ data: Data) -> Data {
        var digest = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes { input in
            digest.withUnsafeMutableBytes { output in
                _ = CC_SHA1(
                    input.baseAddress,
                    CC_LONG(input.count),
                    output.bindMemory(to: UInt8.self).baseAddress
                )
            }
        }
        return digest
    }

    public static func randomBytes(count: Int) throws -> Data {
        guard (0...maximumCMACInput).contains(count) else {
            throw CryptoPrimitiveError.inputTooLarge
        }
        guard count > 0 else { return Data() }
        var result = Data(count: count)
        let status = result.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else {
            secureZero(&result)
            throw CryptoPrimitiveError.securityFailure(status)
        }
        return result
    }

    public static func aesECBEncryptBlock(key: Data, block: Data) throws -> Data {
        guard block.count == aesBlockSize else {
            throw CryptoPrimitiveError.invalidBlockLength
        }
        return try crypt(
            operation: CCOperation(kCCEncrypt),
            options: CCOptions(kCCOptionECBMode),
            key: key,
            iv: nil,
            input: block
        )
    }

    public static func aesCBCEncrypt(
        key: Data,
        iv: Data,
        plaintext: Data
    ) throws -> Data {
        try cbc(
            operation: CCOperation(kCCEncrypt),
            key: key,
            iv: iv,
            input: plaintext
        )
    }

    public static func aesCBCDecrypt(
        key: Data,
        iv: Data,
        ciphertext: Data
    ) throws -> Data {
        try cbc(
            operation: CCOperation(kCCDecrypt),
            key: key,
            iv: iv,
            input: ciphertext
        )
    }

    public static func cmac(key: Data, message: Data) throws -> Data {
        guard key.count == kCCKeySizeAES128 else {
            throw CryptoPrimitiveError.invalidAESKeyLength
        }
        guard message.count <= maximumCMACInput else {
            throw CryptoPrimitiveError.inputTooLarge
        }

        var zero = Data(repeating: 0, count: aesBlockSize)
        var l = try aesECBEncryptBlock(key: key, block: zero)
        var k1 = doubled(l)
        var k2 = doubled(k1)
        defer {
            secureZero(&zero)
            secureZero(&l)
            secureZero(&k1)
            secureZero(&k2)
        }

        let completeLastBlock = !message.isEmpty
            && message.count.isMultiple(of: aesBlockSize)
        let blockCount = max(1, (message.count + aesBlockSize - 1) / aesBlockSize)
        var state = Data(repeating: 0, count: aesBlockSize)
        defer { secureZero(&state) }

        if blockCount > 1 {
            for index in 0..<(blockCount - 1) {
                let start = index * aesBlockSize
                let block = message.subdata(in: start..<(start + aesBlockSize))
                state = try aesECBEncryptBlock(key: key, block: xor(state, block))
            }
        }

        let last: Data
        if completeLastBlock {
            let start = (blockCount - 1) * aesBlockSize
            last = xor(message.subdata(in: start..<(start + aesBlockSize)), k1)
        } else {
            let start = (blockCount - 1) * aesBlockSize
            var padded = Data(message[start..<message.count])
            padded.append(0x80)
            padded.append(Data(repeating: 0, count: aesBlockSize - padded.count))
            last = xor(padded, k2)
            secureZero(&padded)
        }

        return try aesECBEncryptBlock(key: key, block: xor(state, last))
    }

    public static func verifyTag(expected: Data, actual: Data) -> Bool {
        guard expected.count == actual.count else { return false }
        var difference: UInt8 = 0
        for index in expected.indices {
            difference |= expected[index] ^ actual[index]
        }
        return difference == 0
    }

    public static func iso7816Pad(
        _ data: Data,
        blockSize: Int = aesBlockSize
    ) throws -> Data {
        guard blockSize > 0, data.count <= maximumCMACInput - blockSize else {
            throw CryptoPrimitiveError.inputTooLarge
        }
        var result = data
        result.append(0x80)
        let remainder = result.count % blockSize
        if remainder != 0 {
            result.append(Data(repeating: 0, count: blockSize - remainder))
        }
        return result
    }

    public static func iso7816Unpad(
        _ data: Data,
        blockSize: Int = aesBlockSize
    ) throws -> Data {
        guard !data.isEmpty,
              blockSize > 0,
              data.count.isMultiple(of: blockSize) else {
            throw CryptoPrimitiveError.invalidPadding
        }
        var index = data.count
        while index > 0, data[index - 1] == 0 { index -= 1 }
        guard index > 0, data[index - 1] == 0x80 else {
            throw CryptoPrimitiveError.invalidPadding
        }
        return data.prefix(index - 1)
    }

    public static func incrementBigEndianCounter(_ counter: Data) throws -> Data {
        guard !counter.isEmpty else {
            throw CryptoPrimitiveError.invalidBlockLength
        }
        var result = counter
        for index in result.indices.reversed() {
            if result[index] != 0xff {
                result[index] &+= 1
                return result
            }
            result[index] = 0
        }
        secureZero(&result)
        throw CryptoPrimitiveError.counterOverflow
    }

    public static func deriveDNIeChannelKeys(
        terminalSeed: Data,
        cardSeed: Data
    ) throws -> (encryption: Data, mac: Data) {
        guard terminalSeed.count == 32, cardSeed.count == 32 else {
            throw CryptoPrimitiveError.invalidBlockLength
        }
        var combined = xor(terminalSeed, cardSeed)
        defer { secureZero(&combined) }
        var encryptionInput = combined
        encryptionInput.append(contentsOf: [0, 0, 0, 1])
        var macInput = combined
        macInput.append(contentsOf: [0, 0, 0, 2])
        defer {
            secureZero(&encryptionInput)
            secureZero(&macInput)
        }
        return (
            Data(sha256(encryptionInput).prefix(16)),
            Data(sha256(macInput).prefix(16))
        )
    }

    public static func dnieCBCIV(
        key: Data,
        incrementedCounter: Data
    ) throws -> Data {
        try aesECBEncryptBlock(key: key, block: incrementedCounter)
    }

    public static func dnieEncrypt(
        key: Data,
        incrementedCounter: Data,
        plaintext: Data
    ) throws -> Data {
        let padded = try iso7816Pad(plaintext)
        let iv = try dnieCBCIV(key: key, incrementedCounter: incrementedCounter)
        return try aesCBCEncrypt(key: key, iv: iv, plaintext: padded)
    }

    public static func dnieDecrypt(
        key: Data,
        incrementedCounter: Data,
        ciphertext: Data
    ) throws -> Data {
        let iv = try dnieCBCIV(key: key, incrementedCounter: incrementedCounter)
        let padded = try aesCBCDecrypt(key: key, iv: iv, ciphertext: ciphertext)
        return try iso7816Unpad(padded)
    }

    public static func dnieMAC(
        key: Data,
        incrementedCounter: Data,
        paddedMessage: Data
    ) throws -> Data {
        guard incrementedCounter.count == aesBlockSize,
              paddedMessage.count.isMultiple(of: aesBlockSize) else {
            throw CryptoPrimitiveError.invalidBlockLength
        }
        var input = incrementedCounter
        input.append(paddedMessage)
        defer { secureZero(&input) }
        return Data(try cmac(key: key, message: input).prefix(8))
    }

    public static func rawRSASelfTest() throws -> Bool {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2_048,
            kSecAttrIsPermanent: false,
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            let status = error.map {
                Int32(CFErrorGetCode($0.takeRetainedValue()))
            } ?? errSecInternalError
            throw CryptoPrimitiveError.securityFailure(status)
        }

        let blockSize = SecKeyGetBlockSize(publicKey)
        var message = Data(repeating: 0, count: blockSize)
        message[blockSize - 1] = 0x2a
        defer { secureZero(&message) }
        guard let encrypted = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionRaw,
            message as CFData,
            &error
        ) as Data? else {
            throw CryptoPrimitiveError.securityFailure(errSecInternalError)
        }
        guard var decrypted = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionRaw,
            encrypted as CFData,
            &error
        ) as Data? else {
            throw CryptoPrimitiveError.securityFailure(errSecInternalError)
        }
        defer { secureZero(&decrypted) }
        return decrypted.suffix(message.count) == message
    }

    public static func secureZero(_ data: inout Data) {
        data.withUnsafeMutableBytes { buffer in
            if let address = buffer.baseAddress, !buffer.isEmpty {
                _ = memset_s(address, buffer.count, 0, buffer.count)
            }
        }
        data.removeAll(keepingCapacity: false)
    }

    static func doubled(_ block: Data) -> Data {
        precondition(block.count == aesBlockSize)
        var result = Data(repeating: 0, count: aesBlockSize)
        var carry: UInt8 = 0
        for index in block.indices.reversed() {
            let value = block[index]
            result[index] = (value << 1) | carry
            carry = value & 0x80 == 0 ? 0 : 1
        }
        if carry != 0 { result[result.count - 1] ^= 0x87 }
        return result
    }

    private static func cbc(
        operation: CCOperation,
        key: Data,
        iv: Data,
        input: Data
    ) throws -> Data {
        guard iv.count == aesBlockSize else {
            throw CryptoPrimitiveError.invalidIVLength
        }
        guard !input.isEmpty, input.count.isMultiple(of: aesBlockSize) else {
            throw CryptoPrimitiveError.invalidBlockLength
        }
        return try crypt(
            operation: operation,
            options: 0,
            key: key,
            iv: iv,
            input: input
        )
    }

    private static func crypt(
        operation: CCOperation,
        options: CCOptions,
        key: Data,
        iv: Data?,
        input: Data
    ) throws -> Data {
        guard key.count == kCCKeySizeAES128 else {
            throw CryptoPrimitiveError.invalidAESKeyLength
        }
        let capacity = input.count + aesBlockSize
        var output = Data(count: capacity)
        var moved = 0
        let status = key.withUnsafeBytes { keyBytes in
            input.withUnsafeBytes { inputBytes in
                output.withUnsafeMutableBytes { outputBytes in
                    if let iv {
                        return iv.withUnsafeBytes { ivBytes in
                            CCCrypt(
                                operation,
                                CCAlgorithm(kCCAlgorithmAES),
                                options,
                                keyBytes.baseAddress,
                                key.count,
                                ivBytes.baseAddress,
                                inputBytes.baseAddress,
                                input.count,
                                outputBytes.baseAddress,
                                capacity,
                                &moved
                            )
                        }
                    }
                    return CCCrypt(
                        operation,
                        CCAlgorithm(kCCAlgorithmAES),
                        options,
                        keyBytes.baseAddress,
                        key.count,
                        nil,
                        inputBytes.baseAddress,
                        input.count,
                        outputBytes.baseAddress,
                        capacity,
                        &moved
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            secureZero(&output)
            throw CryptoPrimitiveError.commonCryptoFailure(status)
        }
        output.removeSubrange(moved..<output.count)
        return output
    }

    private static func xor(_ lhs: Data, _ rhs: Data) -> Data {
        precondition(lhs.count == rhs.count)
        var result = Data(count: lhs.count)
        for index in lhs.indices { result[index] = lhs[index] ^ rhs[index] }
        return result
    }
}

public struct EphemeralChannelState: Sendable {
    private var encryptionKey: Data
    private var macKey: Data
    private var counter: Data
    public private(set) var isDestroyed = false

    public init(encryptionKey: Data, macKey: Data, counter: Data) throws {
        guard encryptionKey.count == 16,
              macKey.count == 16,
              counter.count == 16 else {
            throw CryptoPrimitiveError.invalidBlockLength
        }
        self.encryptionKey = encryptionKey
        self.macKey = macKey
        self.counter = counter
    }

    public mutating func nextCounter() throws -> Data {
        guard !isDestroyed else { throw CryptoPrimitiveError.destroyedState }
        counter = try CryptoPrimitives.incrementBigEndianCounter(counter)
        return counter
    }

    public mutating func withKeys<Result>(
        _ body: (Data, Data) throws -> Result
    ) throws -> Result {
        guard !isDestroyed else { throw CryptoPrimitiveError.destroyedState }
        return try body(encryptionKey, macKey)
    }

    public mutating func destroy() {
        CryptoPrimitives.secureZero(&encryptionKey)
        CryptoPrimitives.secureZero(&macKey)
        CryptoPrimitives.secureZero(&counter)
        isDestroyed = true
    }
}
