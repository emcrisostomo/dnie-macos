import Foundation

public enum IdentityOperationPolicy {
    public static func supports(
        identity: DNIeIdentityDescriptor,
        objectID: OpaqueObjectID,
        operation: CardOperationKind,
        algorithm: KeyAlgorithm
    ) -> Bool {
        objectID == identity.objectID
            && operation == .sign
            && identity.canSign
            && identity.keyReference.usage.contains(.sign)
            && identity.algorithms.contains(algorithm)
    }
}

public extension KeyAlgorithm {
    init?(exactPlatformName: String) {
        self.init(rawValue: exactPlatformName)
    }
}
