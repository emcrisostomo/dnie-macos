import Foundation

public struct ConnectionGeneration: Hashable, Sendable {
    public let rawValue: UUID

    public init(rawValue: UUID = UUID()) {
        self.rawValue = rawValue
    }
}

public struct CorrelationID: Hashable, Sendable {
    public let rawValue: UUID

    public init(rawValue: UUID = UUID()) {
        self.rawValue = rawValue
    }
}

public struct ProfileVersion: Hashable, Sendable {
    public let rawValue: String

    public init(_ rawValue: String) {
        precondition(!rawValue.isEmpty)
        self.rawValue = rawValue
    }
}

public enum CardConnectionState: Sendable, Equatable {
    case absent
    case candidate
    case recognized(profileVersion: ProfileVersion)
    case invalid
}

public enum PublicationState: Sendable, Equatable {
    case unpublished
    case published
    case invalid
}

public enum TokenLifecycleState: Sendable, Equatable {
    case absent
    case candidate
    case publicReady
    case authPending
    case authorized
    case invalid
}

public struct CardConnectionSnapshot: Sendable, Equatable {
    public let generation: ConnectionGeneration?
    public let state: CardConnectionState
    public let publicationState: PublicationState

    public init(
        generation: ConnectionGeneration?,
        state: CardConnectionState,
        publicationState: PublicationState
    ) {
        self.generation = generation
        self.state = state
        self.publicationState = publicationState
    }
}

public struct OpaqueObjectID: Hashable, Sendable {
    public let bytes: Data

    public init(bytes: Data) {
        precondition(!bytes.isEmpty)
        self.bytes = bytes
    }
}

public struct CardPath: Hashable, Sendable {
    public let components: [UInt16]

    public init(components: [UInt16]) {
        precondition(!components.isEmpty && components.count <= 8)
        self.components = components
    }
}

public struct KeyUsage: OptionSet, Hashable, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    public static let sign = KeyUsage(rawValue: 1 << 0)
    public static let authenticate = KeyUsage(rawValue: 1 << 1)
}

public enum PKCS15ObjectType: Sendable, Equatable {
    case certificate
    case privateKey
    case authenticationReference
}

public struct PKCS15ObjectReference: Sendable, Equatable {
    public let objectType: PKCS15ObjectType
    public let ckaID: Data
    public let label: String?
    public let path: CardPath
    public let usage: KeyUsage
    public let keyReference: UInt8?
    public let authenticationReference: Data?

    public init(
        objectType: PKCS15ObjectType,
        ckaID: Data,
        label: String?,
        path: CardPath,
        usage: KeyUsage,
        keyReference: UInt8?,
        authenticationReference: Data?
    ) {
        precondition(!ckaID.isEmpty)
        self.objectType = objectType
        self.ckaID = ckaID
        self.label = label
        self.path = path
        self.usage = usage
        self.keyReference = keyReference
        self.authenticationReference = authenticationReference
    }
}

public enum CertificateRole: Sendable, Equatable {
    case authentication
    case signature
    case intermediate
    case component
}

public enum KeyAlgorithm: String, Hashable, Sendable {
    case rsaSignatureDigestPKCS1v15SHA256
}

public struct DNIeIdentityDescriptor: Sendable, Equatable {
    public let objectID: OpaqueObjectID
    public let certificateDER: Data
    public let certificateRole: CertificateRole
    public let keyReference: PKCS15ObjectReference
    public let canSign: Bool
    public let isSuitableForLogin: Bool
    public let constraints: [CardOperationKind: Data]
    public let algorithms: Set<KeyAlgorithm>

    public init(
        objectID: OpaqueObjectID,
        certificateDER: Data,
        certificateRole: CertificateRole,
        keyReference: PKCS15ObjectReference,
        canSign: Bool,
        isSuitableForLogin: Bool = false,
        constraints: [CardOperationKind: Data],
        algorithms: Set<KeyAlgorithm>
    ) {
        precondition(!certificateDER.isEmpty)
        self.objectID = objectID
        self.certificateDER = certificateDER
        self.certificateRole = certificateRole
        self.keyReference = keyReference
        self.canSign = canSign
        self.isSuitableForLogin = isSuitableForLogin
        self.constraints = constraints
        self.algorithms = algorithms
    }
}

public struct DNIeSupportingCertificateDescriptor: Sendable, Equatable {
    public let objectID: OpaqueObjectID
    public let certificateDER: Data
    public let certificateRole: CertificateRole

    public init(
        objectID: OpaqueObjectID,
        certificateDER: Data,
        certificateRole: CertificateRole
    ) {
        precondition(!certificateDER.isEmpty)
        precondition(certificateRole == .intermediate)
        self.objectID = objectID
        self.certificateDER = certificateDER
        self.certificateRole = certificateRole
    }
}

public enum CardOperationKind: String, Hashable, Sendable {
    case discover
    case authenticate
    case sign
}

public struct CardOperationMetadata: Hashable, Sendable {
    public let kind: CardOperationKind
    public let objectID: OpaqueObjectID?
    public let algorithm: KeyAlgorithm?
    public let correlationID: CorrelationID

    public init(
        kind: CardOperationKind,
        objectID: OpaqueObjectID? = nil,
        algorithm: KeyAlgorithm? = nil,
        correlationID: CorrelationID = CorrelationID()
    ) {
        self.kind = kind
        self.objectID = objectID
        self.algorithm = algorithm
        self.correlationID = correlationID
    }
}
