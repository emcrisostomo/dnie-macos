import Foundation
import Security

public enum CredentialGeneration: String, Sendable, Equatable {
    case generation2 = "generation_2"
}

public enum TerminalCredentialRole: String, Sendable, Hashable, Codable {
    case user
    case pin
}

public enum CredentialFixtureError: Error, Sendable, Equatable {
    case malformedFixture
    case unsupportedGeneration
    case ambiguousGeneration
    case provenanceMismatch
    case manifestMismatch
    case missingField
    case invalidPrivateKeyBinding
}

public struct CredentialProvenanceMetadata: Sendable, Equatable {
    public let fixtureVersion: Int
    public let setID: String
    public let manifestSHA256: String
    public let sourceSHA256: String
    public let officialDistributionSHA256: String
    public let orderedFieldNames: [String]
    public let requiredPrivateKeyRoles: Set<TerminalCredentialRole>

    public static let generation2 = CredentialProvenanceMetadata(
        fixtureVersion: 2,
        setID: CredentialGeneration.generation2.rawValue,
        manifestSHA256: "3bac8e7a79c62ee35b9ba7b47e3d3fbbb4d16a6461cb89f59f744f55652fff6d",
        sourceSHA256: "6528a9662523362f53479440c6611a241cda1940a2b5a05fa5deb4c8bf3cba4a",
        officialDistributionSHA256: "d2de4308190433a22683ef7fa85637b446f2a9420e35e50b86314a5590c46bc2",
        orderedFieldNames: [
            "icc_root_ca_modulus_1",
            "ifd_modulus_1",
            "ifd_pin_modulus_1",
            "ifd_private_exponent_1",
            "ifd_pin_private_exponent_1",
            "C_CV_CA_CS_AUT_cert_1",
            "C_CV_IFDUser_AUT_cert_1",
            "C_CV_IFDUser_AUT_pin_cert_1",
            "cvc_intca_keyref_1",
            "cvc_ifd_keyref_1",
            "cvc_ifd_keyref_pin_1",
            "sn_ifd_1",
            "sn_ifd_pin_1",
            "icc_root_ca_public_exponent",
            "ifd_public_exponent",
            "ifd_pin_public_exponent",
            "root_ca_keyref",
            "icc_priv_keyref",
        ],
        requiredPrivateKeyRoles: [.user, .pin]
    )

    private init(
        fixtureVersion: Int,
        setID: String,
        manifestSHA256: String,
        sourceSHA256: String,
        officialDistributionSHA256: String,
        orderedFieldNames: [String],
        requiredPrivateKeyRoles: Set<TerminalCredentialRole>
    ) {
        self.fixtureVersion = fixtureVersion
        self.setID = setID
        self.manifestSHA256 = manifestSHA256
        self.sourceSHA256 = sourceSHA256
        self.officialDistributionSHA256 = officialDistributionSHA256
        self.orderedFieldNames = orderedFieldNames
        self.requiredPrivateKeyRoles = requiredPrivateKeyRoles
    }
}

public enum CredentialGenerationSelector {
    public static func select(
        historicalIssuerMatch: Bool,
        generation2IssuerMatch: Bool
    ) throws -> CredentialGeneration {
        guard !(historicalIssuerMatch && generation2IssuerMatch) else {
            throw CredentialFixtureError.ambiguousGeneration
        }
        guard !historicalIssuerMatch, generation2IssuerMatch else {
            throw CredentialFixtureError.unsupportedGeneration
        }
        return .generation2
    }
}

public struct VerifiedCredentialSet: Sendable {
    public let generation: CredentialGeneration
    public let fieldNames: [String]
    public let privateKeyRoles: Set<TerminalCredentialRole>

    let fields: [String: Data]
    let privateKeysPKCS1: [TerminalCredentialRole: Data]

    func field(named name: String) throws -> Data {
        guard let value = fields[name] else {
            throw CredentialFixtureError.missingField
        }
        return value
    }

    func privateKeyPKCS1(role: TerminalCredentialRole) throws -> Data {
        guard let value = privateKeysPKCS1[role] else {
            throw CredentialFixtureError.missingField
        }
        return value
    }
}

public enum CredentialFixtureVerifier {
    private static let maximumFixtureLength = 65_536
    private static let maximumFieldLength = 4_096

    public static func verifyGeneration2(_ encoded: Data) throws -> VerifiedCredentialSet {
        guard !encoded.isEmpty, encoded.count <= maximumFixtureLength else {
            throw CredentialFixtureError.malformedFixture
        }
        let fixture: EncodedCredentialFixture
        do {
            fixture = try JSONDecoder().decode(EncodedCredentialFixture.self, from: encoded)
        } catch {
            throw CredentialFixtureError.malformedFixture
        }

        let expected = CredentialProvenanceMetadata.generation2
        guard fixture.fixtureVersion == expected.fixtureVersion else {
            throw CredentialFixtureError.provenanceMismatch
        }
        guard fixture.setID == expected.setID else {
            throw CredentialFixtureError.unsupportedGeneration
        }
        guard fixture.sourceSHA256 == expected.sourceSHA256,
              fixture.officialDistributionSHA256 == expected.officialDistributionSHA256,
              fixture.orderedFieldNames == expected.orderedFieldNames else {
            throw CredentialFixtureError.provenanceMismatch
        }
        guard fixture.manifestSHA256 == expected.manifestSHA256 else {
            throw CredentialFixtureError.manifestMismatch
        }
        guard Set(fixture.fieldsHex.keys) == Set(expected.orderedFieldNames),
              fixture.fieldsHex.count == expected.orderedFieldNames.count else {
            throw CredentialFixtureError.missingField
        }

        var decodedFields: [String: Data] = [:]
        var manifestInput = Data()
        for name in expected.orderedFieldNames {
            guard let encodedField = fixture.fieldsHex[name] else {
                throw CredentialFixtureError.missingField
            }
            let field = try decodeHex(encodedField)
            guard !field.isEmpty, field.count <= maximumFieldLength else {
                throw CredentialFixtureError.malformedFixture
            }
            decodedFields[name] = field
            manifestInput.append(Data(name.utf8))
            manifestInput.append(0)
            var length = UInt32(field.count).bigEndian
            withUnsafeBytes(of: &length) { manifestInput.append(contentsOf: $0) }
            manifestInput.append(field)
        }
        defer { CryptoPrimitives.secureZero(&manifestInput) }
        let computedManifest = hex(CryptoPrimitives.sha256(manifestInput))
        guard computedManifest == expected.manifestSHA256 else {
            throw CredentialFixtureError.manifestMismatch
        }

        var privateKeys: [TerminalCredentialRole: Data] = [:]
        let encodedRoles = Set(fixture.localPrivateKeysPKCS1Hex.keys)
        guard encodedRoles == Set(expected.requiredPrivateKeyRoles.map(\.rawValue)) else {
            throw CredentialFixtureError.missingField
        }
        for role in expected.requiredPrivateKeyRoles {
            guard let encodedKey = fixture.localPrivateKeysPKCS1Hex[role.rawValue] else {
                throw CredentialFixtureError.missingField
            }
            let key = try decodeHex(encodedKey)
            guard !key.isEmpty, key.count <= maximumFieldLength else {
                throw CredentialFixtureError.malformedFixture
            }
            privateKeys[role] = key
        }

        try verifyPrivateKeyBinding(
            privateKey: privateKeys[.user],
            modulus: decodedFields["ifd_modulus_1"],
            exponent: decodedFields["ifd_public_exponent"]
        )
        try verifyPrivateKeyBinding(
            privateKey: privateKeys[.pin],
            modulus: decodedFields["ifd_pin_modulus_1"],
            exponent: decodedFields["ifd_pin_public_exponent"]
        )

        return VerifiedCredentialSet(
            generation: .generation2,
            fieldNames: expected.orderedFieldNames,
            privateKeyRoles: expected.requiredPrivateKeyRoles,
            fields: decodedFields,
            privateKeysPKCS1: privateKeys
        )
    }

    private static func verifyPrivateKeyBinding(
        privateKey: Data?,
        modulus: Data?,
        exponent: Data?
    ) throws {
        guard let privateKey, let modulus, let exponent else {
            throw CredentialFixtureError.missingField
        }
        let publicRepresentation = derSequence([
            derInteger(modulus),
            derInteger(exponent),
        ])
        let common: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: modulus.count * 8,
            kSecAttrIsPermanent: false,
        ]
        var error: Unmanaged<CFError>?
        var publicAttributes = common
        publicAttributes[kSecAttrKeyClass] = kSecAttrKeyClassPublic
        var privateAttributes = common
        privateAttributes[kSecAttrKeyClass] = kSecAttrKeyClassPrivate
        guard let importedPublic = SecKeyCreateWithData(
            publicRepresentation as CFData,
            publicAttributes as CFDictionary,
            &error
        ), let importedPrivate = SecKeyCreateWithData(
            privateKey as CFData,
            privateAttributes as CFDictionary,
            &error
        ), SecKeyGetBlockSize(importedPublic) == modulus.count,
           SecKeyGetBlockSize(importedPrivate) == modulus.count else {
            throw CredentialFixtureError.invalidPrivateKeyBinding
        }

        var message = Data(repeating: 0, count: modulus.count)
        message[message.count - 1] = 0x2a
        defer { CryptoPrimitives.secureZero(&message) }
        guard let encrypted = SecKeyCreateEncryptedData(
            importedPublic,
            .rsaEncryptionRaw,
            message as CFData,
            &error
        ) as Data?, var decrypted = SecKeyCreateDecryptedData(
            importedPrivate,
            .rsaEncryptionRaw,
            encrypted as CFData,
            &error
        ) as Data? else {
            throw CredentialFixtureError.invalidPrivateKeyBinding
        }
        defer { CryptoPrimitives.secureZero(&decrypted) }
        guard Data(decrypted.suffix(message.count)) == message else {
            throw CredentialFixtureError.invalidPrivateKeyBinding
        }
    }

    private static func decodeHex(_ encoded: String) throws -> Data {
        guard !encoded.isEmpty,
              encoded.count.isMultiple(of: 2),
              encoded.count / 2 <= maximumFieldLength else {
            throw CredentialFixtureError.malformedFixture
        }
        var result = Data(capacity: encoded.count / 2)
        var index = encoded.startIndex
        while index < encoded.endIndex {
            let next = encoded.index(index, offsetBy: 2)
            guard let byte = UInt8(encoded[index..<next], radix: 16) else {
                throw CredentialFixtureError.malformedFixture
            }
            result.append(byte)
            index = next
        }
        return result
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func derInteger(_ unsigned: Data) -> Data {
        var normalized = Data(unsigned.drop(while: { $0 == 0 }))
        if normalized.isEmpty { normalized.append(0) }
        if normalized[0] & 0x80 != 0 { normalized.insert(0, at: 0) }
        return Data([0x02]) + derLength(normalized.count) + normalized
    }

    private static func derSequence(_ elements: [Data]) -> Data {
        let body = elements.reduce(into: Data()) { $0.append($1) }
        return Data([0x30]) + derLength(body.count) + body
    }

    private static func derLength(_ count: Int) -> Data {
        if count < 0x80 { return Data([UInt8(count)]) }
        var value = count
        var bytes = Data()
        while value > 0 {
            bytes.insert(UInt8(value & 0xff), at: 0)
            value >>= 8
        }
        return Data([0x80 | UInt8(bytes.count)]) + bytes
    }
}

private struct EncodedCredentialFixture: Decodable {
    let fixtureVersion: Int
    let setID: String
    let manifestSHA256: String
    let sourceSHA256: String
    let officialDistributionSHA256: String
    let orderedFieldNames: [String]
    let fieldsHex: [String: String]
    let localPrivateKeysPKCS1Hex: [String: String]

    enum CodingKeys: String, CodingKey {
        case fixtureVersion = "fixture_version"
        case setID = "set_id"
        case manifestSHA256 = "manifest_sha256"
        case sourceSHA256 = "source_sha256"
        case officialDistributionSHA256 = "official_binary_sha256"
        case orderedFieldNames = "ordered_field_names"
        case fieldsHex = "fields_hex"
        case localPrivateKeysPKCS1Hex = "local_private_keys_pkcs1_hex"
    }
}
