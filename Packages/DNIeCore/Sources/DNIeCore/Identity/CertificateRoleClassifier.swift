import Foundation

public enum CertificateRoleClassificationError: Error, Sendable, Equatable {
    case invalidCertificate
    case contradictoryUsage
}

public enum CertificateRoleClassifier {
    private static let keyUsageOID = Data([0x55, 0x1D, 0x0F])
    private static let basicConstraintsOID = Data([0x55, 0x1D, 0x13])

    public static func classify(der: Data) throws -> CertificateRole? {
        let certificate = try one(der, tag: 0x30)
        let certificateFields = try BoundedDERReader.parseAll(
            certificate.value,
            maximumElements: 4
        )
        guard let tbs = certificateFields.first, tbs.tag == 0x30 else {
            throw CertificateRoleClassificationError.invalidCertificate
        }
        let tbsFields = try BoundedDERReader.parseAll(tbs.value, maximumElements: 16)
        guard let extensionsWrapper = tbsFields.first(where: { $0.tag == 0xA3 }) else {
            return nil
        }
        let extensionsSequence = try one(extensionsWrapper.value, tag: 0x30)
        let extensions = try BoundedDERReader.parseAll(
            extensionsSequence.value,
            maximumElements: 32
        )
        var keyUsage: Set<Int>?
        var isCA = false
        for encodedExtension in extensions {
            guard encodedExtension.tag == 0x30 else {
                throw CertificateRoleClassificationError.invalidCertificate
            }
            let fields = try BoundedDERReader.parseAll(
                encodedExtension.value,
                maximumElements: 3
            )
            guard let oid = fields.first, oid.tag == 0x06,
                  let value = fields.last, value.tag == 0x04 else {
                throw CertificateRoleClassificationError.invalidCertificate
            }
            if oid.value == keyUsageOID {
                let bitString = try one(value.value, tag: 0x03)
                keyUsage = try bitPositions(bitString.value)
            } else if oid.value == basicConstraintsOID {
                let constraints = try one(value.value, tag: 0x30)
                let values = try BoundedDERReader.parseAll(
                    constraints.value,
                    maximumElements: 2
                )
                if let boolean = values.first, boolean.tag == 0x01 {
                    guard boolean.value.count == 1 else {
                        throw CertificateRoleClassificationError.invalidCertificate
                    }
                    isCA = boolean.value.first != 0
                }
            }
        }
        if isCA { return .intermediate }
        guard let keyUsage else { return nil }
        let digitalSignature = keyUsage.contains(0)
        let contentCommitment = keyUsage.contains(1)
        guard !(digitalSignature && contentCommitment) else {
            throw CertificateRoleClassificationError.contradictoryUsage
        }
        if contentCommitment { return .signature }
        if digitalSignature { return .authentication }
        return nil
    }

    private static func one(_ data: Data, tag: UInt8) throws -> BoundedDERTLV {
        let values = try BoundedDERReader.parseAll(data, maximumElements: 2)
        guard values.count == 1, values[0].tag == tag else {
            throw CertificateRoleClassificationError.invalidCertificate
        }
        return values[0]
    }

    private static func bitPositions(_ value: Data) throws -> Set<Int> {
        let bytes = [UInt8](value)
        guard bytes.count > 1, (0...7).contains(Int(bytes[0])) else {
            throw CertificateRoleClassificationError.invalidCertificate
        }
        let unused = Int(bytes[0])
        let payload = Array(bytes.dropFirst())
        if unused > 0 {
            let mask = UInt8((1 << unused) - 1)
            guard payload.last! & mask == 0 else {
                throw CertificateRoleClassificationError.invalidCertificate
            }
        }
        let count = payload.count * 8 - unused
        return Set((0..<count).filter {
            payload[$0 / 8] & (0x80 >> UInt8($0 % 8)) != 0
        })
    }
}
