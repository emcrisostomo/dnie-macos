import CryptoKit
import CryptoTokenKit
import DNIeCore
import Foundation
import Security

enum PlatformItemMappingError: Error {
    case invalidCertificate
    case certificateProxyInitialization
    case keyProxyInitialization
}

struct PlatformTokenPlan {
    static let expectedAID = Data([
        0xA0, 0x00, 0x00, 0x00, 0x63, 0x50,
        0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35,
    ])

    let instanceID: String
    let keychainItems: [TKTokenKeychainItem]
    let certificateObjectIDs: [Data]
    let keyObjectIDs: [Data]
    let identitiesByKeyObjectID: [Data: DNIeIdentityDescriptor]

    static func make(
        selectedAID: Data?,
        opaqueInstanceInput: Data,
        identities: [DNIeIdentityDescriptor],
        supportingCertificates: [DNIeSupportingCertificateDescriptor] = []
    ) throws -> PlatformTokenPlan? {
        guard selectedAID == expectedAID,
              !opaqueInstanceInput.isEmpty,
              !identities.isEmpty else {
            return nil
        }

        let instanceDigest = domainSeparatedDigest(
            domain: "token-instance",
            input: opaqueInstanceInput
        )
        var items: [TKTokenKeychainItem] = []
        var certificateObjectIDs: [Data] = []
        var keyObjectIDs: [Data] = []
        var identitiesByKeyObjectID: [Data: DNIeIdentityDescriptor] = [:]

        for identity in identities {
            guard let certificate = SecCertificateCreateWithData(
                nil,
                identity.certificateDER as CFData
            ) else {
                throw PlatformItemMappingError.invalidCertificate
            }
            let certificateObjectID = domainSeparatedDigest(
                domain: "certificate-object",
                input: identity.objectID.bytes
            )
            let keyObjectID = domainSeparatedDigest(
                domain: "private-key-object",
                input: identity.objectID.bytes
            )
            guard let certificateItem = TKTokenKeychainCertificate(
                certificate: certificate,
                objectID: certificateObjectID
            ) else {
                throw PlatformItemMappingError.certificateProxyInitialization
            }
            guard let keyItem = TKTokenKeychainKey(
                certificate: certificate,
                objectID: keyObjectID
            ) else {
                throw PlatformItemMappingError.keyProxyInitialization
            }

            certificateItem.label = certificateLabel(for: identity.certificateRole)
            keyItem.label = keyLabel(for: identity.certificateRole)
            keyItem.keyType = kSecAttrKeyTypeRSA as String
            // The PKCS#15 parser has already failed closed unless this is a
            // native 2,048-bit RSA key. Set the value explicitly so it is
            // serialized into CryptoTokenKit metadata, matching the proven
            // T026/T027 provider rather than relying on a computed getter.
            keyItem.keySizeInBits = 2_048
            keyItem.applicationTag = keyObjectID
            keyItem.canDecrypt = false
            keyItem.canSign = identity.canSign
            keyItem.canPerformKeyExchange = false
            keyItem.isSuitableForLogin = false
            keyItem.constraints = operationConstraints(for: identity)

            items.append(contentsOf: [certificateItem, keyItem])
            certificateObjectIDs.append(certificateObjectID)
            keyObjectIDs.append(keyObjectID)
            identitiesByKeyObjectID[keyObjectID] = identity
        }

        for supportingCertificate in supportingCertificates {
            guard let certificate = SecCertificateCreateWithData(
                nil,
                supportingCertificate.certificateDER as CFData
            ) else {
                throw PlatformItemMappingError.invalidCertificate
            }
            let certificateObjectID = domainSeparatedDigest(
                domain: "supporting-certificate-object",
                input: supportingCertificate.objectID.bytes
            )
            guard let certificateItem = TKTokenKeychainCertificate(
                certificate: certificate,
                objectID: certificateObjectID
            ) else {
                throw PlatformItemMappingError.certificateProxyInitialization
            }
            certificateItem.label = certificateLabel(
                for: supportingCertificate.certificateRole
            )
            items.append(certificateItem)
            certificateObjectIDs.append(certificateObjectID)
        }

        return PlatformTokenPlan(
            instanceID: "org.dniemacos.dnietoken.instance.v1." + hex(instanceDigest),
            keychainItems: items,
            certificateObjectIDs: certificateObjectIDs,
            keyObjectIDs: keyObjectIDs,
            identitiesByKeyObjectID: identitiesByKeyObjectID
        )
    }

    static func supportsSign(
        identity: DNIeIdentityDescriptor,
        algorithm: KeyAlgorithm
    ) -> Bool {
        IdentityOperationPolicy.supports(
            identity: identity,
            objectID: identity.objectID,
            operation: .sign,
            algorithm: algorithm
        )
    }

    private static func operationConstraints(
        for identity: DNIeIdentityDescriptor
    ) -> [NSNumber: any NSSecureCoding] {
        guard identity.canSign,
              let constraint = identity.constraints[.sign]
                ?? identity.constraints[.authenticate] else {
            return [:]
        }
        return [
            NSNumber(value: TKTokenOperation.signData.rawValue): constraint as NSData,
        ]
    }

    private static func certificateLabel(for role: CertificateRole) -> String {
        switch role {
        case .authentication: "Spanish DNIe Authentication Certificate"
        case .signature: "Spanish DNIe Signature Certificate"
        case .intermediate: "Spanish DNIe Intermediate Certificate"
        case .component: "Spanish DNIe Component Certificate"
        }
    }

    private static func keyLabel(for role: CertificateRole) -> String {
        switch role {
        case .authentication: "Spanish DNIe Authentication Key"
        case .signature: "Spanish DNIe Signature Key"
        case .intermediate: "Spanish DNIe Intermediate Key"
        case .component: "Spanish DNIe Component Key"
        }
    }

    private static func domainSeparatedDigest(domain: String, input: Data) -> Data {
        var material = Data("org.dniemacos.platform/\(domain)/v1\0".utf8)
        material.append(input)
        return Data(SHA256.hash(data: material))
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
