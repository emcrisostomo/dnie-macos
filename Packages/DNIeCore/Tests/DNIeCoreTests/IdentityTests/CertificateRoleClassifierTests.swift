@testable import DNIeCore
import Foundation
import XCTest

final class CertificateRoleClassifierTests: XCTestCase {
    func testKeyUsageClassifiesCitizenRolesWithoutLabels() throws {
        XCTAssertEqual(
            try CertificateRoleClassifier.classify(der: certificate(keyUsageByte: 0x80)),
            .authentication
        )
        XCTAssertEqual(
            try CertificateRoleClassifier.classify(der: certificate(keyUsageByte: 0x40)),
            .signature
        )
        XCTAssertThrowsError(try CertificateRoleClassifier.classify(
            der: certificate(keyUsageByte: 0xC0)
        ))
    }

    func testCAConstraintExcludesCertificateFromCitizenRoles() throws {
        XCTAssertEqual(
            try CertificateRoleClassifier.classify(
                der: certificate(keyUsageByte: 0x80, isCA: true)
            ),
            .intermediate
        )
    }

    private func certificate(keyUsageByte: UInt8, isCA: Bool = false) -> Data {
        let keyUsage = tlv(0x30, tlv(0x06, Data([0x55, 0x1D, 0x0F]))
            + tlv(0x04, tlv(0x03, Data([0x06, keyUsageByte]))))
        var extensions = keyUsage
        if isCA {
            extensions += tlv(0x30, tlv(0x06, Data([0x55, 0x1D, 0x13]))
                + tlv(0x04, tlv(0x30, tlv(0x01, Data([0xFF])))))
        }
        let tbs = tlv(0x30, tlv(0xA3, tlv(0x30, extensions)))
        return tlv(0x30, tbs + tlv(0x30, Data()) + tlv(0x03, Data([0x00])))
    }

    private func tlv(_ tag: UInt8, _ value: Data) -> Data {
        precondition(value.count < 128)
        return Data([tag, UInt8(value.count)]) + value
    }
}
