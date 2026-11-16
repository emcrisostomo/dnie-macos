import Foundation
import Security

public final class RawRSAKey: @unchecked Sendable {
    public let modulus: Data
    public let publicExponent: Data
    private let key: SecKey
    private let isPrivate: Bool

    public convenience init(publicModulus: Data, publicExponent: Data) throws {
        guard !publicModulus.isEmpty, !publicExponent.isEmpty else {
            throw CryptoPrimitiveError.invalidRSAKey
        }
        try self.init(
            representation: RawRSADER.sequence([
                RawRSADER.integer(publicModulus),
                RawRSADER.integer(publicExponent),
            ]),
            modulus: publicModulus,
            publicExponent: publicExponent,
            keyClass: kSecAttrKeyClassPublic
        )
    }

    public convenience init(
        privatePKCS1: Data,
        modulus: Data,
        publicExponent: Data
    ) throws {
        try self.init(
            representation: privatePKCS1,
            modulus: modulus,
            publicExponent: publicExponent,
            keyClass: kSecAttrKeyClassPrivate
        )
    }

    private init(
        representation: Data,
        modulus: Data,
        publicExponent: Data,
        keyClass: CFString
    ) throws {
        guard !representation.isEmpty,
              !modulus.isEmpty,
              !publicExponent.isEmpty else {
            throw CryptoPrimitiveError.invalidRSAKey
        }
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: keyClass,
            kSecAttrKeySizeInBits: modulus.count * 8,
            kSecAttrIsPermanent: false,
        ]
        var error: Unmanaged<CFError>?
        guard let imported = SecKeyCreateWithData(
            representation as CFData,
            attributes as CFDictionary,
            &error
        ) else {
            let status = error.map {
                Int32(CFErrorGetCode($0.takeRetainedValue()))
            } ?? errSecDecode
            throw CryptoPrimitiveError.securityFailure(status)
        }
        guard SecKeyGetBlockSize(imported) == modulus.count else {
            throw CryptoPrimitiveError.invalidRSAKey
        }
        key = imported
        self.modulus = modulus
        self.publicExponent = publicExponent
        isPrivate = keyClass == kSecAttrKeyClassPrivate
    }

    public func publicOperation(_ value: Data) throws -> Data {
        guard !isPrivate, value.count == modulus.count else {
            throw CryptoPrimitiveError.invalidRSAValue
        }
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCreateEncryptedData(
            key,
            .rsaEncryptionRaw,
            value as CFData,
            &error
        ) as Data? else {
            let status = error.map {
                Int32(CFErrorGetCode($0.takeRetainedValue()))
            } ?? errSecInternalError
            throw CryptoPrimitiveError.securityFailure(status)
        }
        return leftPadded(result, to: modulus.count)
    }

    public func privateOperation(_ value: Data) throws -> Data {
        guard isPrivate, value.count == modulus.count else {
            throw CryptoPrimitiveError.invalidRSAValue
        }
        var error: Unmanaged<CFError>?
        guard let result = SecKeyCreateDecryptedData(
            key,
            .rsaEncryptionRaw,
            value as CFData,
            &error
        ) as Data? else {
            let status = error.map {
                Int32(CFErrorGetCode($0.takeRetainedValue()))
            } ?? errSecInternalError
            throw CryptoPrimitiveError.securityFailure(status)
        }
        return leftPadded(result, to: modulus.count)
    }
}

public enum FixedWidthUnsigned {
    public static func subtract(_ lhs: Data, _ rhs: Data) throws -> Data {
        guard lhs.count == rhs.count,
              compare(lhs, rhs) != .orderedAscending else {
            throw CryptoPrimitiveError.invalidRSAValue
        }
        var output = Data(count: lhs.count)
        var borrow = 0
        for index in lhs.indices.reversed() {
            var value = Int(lhs[index]) - Int(rhs[index]) - borrow
            if value < 0 {
                value += 256
                borrow = 1
            } else {
                borrow = 0
            }
            output[index] = UInt8(value)
        }
        guard borrow == 0 else {
            throw CryptoPrimitiveError.invalidRSAValue
        }
        return output
    }

    public static func minimumSignature(_ signature: Data, modulus: Data) throws -> Data {
        guard signature.count == modulus.count else {
            throw CryptoPrimitiveError.invalidRSAValue
        }
        let complement = try subtract(modulus, signature)
        return compare(signature, complement) == .orderedDescending
            ? complement
            : signature
    }

    public static func compare(_ lhs: Data, _ rhs: Data) -> ComparisonResult {
        precondition(lhs.count == rhs.count)
        for index in lhs.indices {
            if lhs[index] < rhs[index] { return .orderedAscending }
            if lhs[index] > rhs[index] { return .orderedDescending }
        }
        return .orderedSame
    }
}

private enum RawRSADER {
    static func integer(_ unsigned: Data) -> Data {
        var normalized = Data(unsigned.drop(while: { $0 == 0 }))
        if normalized.isEmpty { normalized.append(0) }
        if normalized[0] & 0x80 != 0 { normalized.insert(0, at: 0) }
        return Data([0x02]) + length(normalized.count) + normalized
    }

    static func sequence(_ elements: [Data]) -> Data {
        let body = elements.reduce(into: Data()) { $0.append($1) }
        return Data([0x30]) + length(body.count) + body
    }

    private static func length(_ count: Int) -> Data {
        if count < 0x80 { return Data([UInt8(count)]) }
        var value = count
        var bytes = Data()
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)]) + bytes
    }
}

private func leftPadded(_ value: Data, to count: Int) -> Data {
    if value.count >= count { return value.suffix(count) }
    return Data(repeating: 0, count: count - value.count) + value
}
