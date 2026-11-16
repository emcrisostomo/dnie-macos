import Foundation

public enum EvidenceState: String, Sendable, CaseIterable {
    case documented = "DOCUMENTED"
    case experimentallyVerified = "EXPERIMENTALLY VERIFIED"
    case inferred = "INFERRED"
    case unknown = "UNKNOWN"

    public var enablesCapability: Bool {
        self == .documented || self == .experimentallyVerified
    }
}

public struct EvidenceRequirement: Sendable, Equatable {
    public let evidenceID: String
    public let state: EvidenceState

    public init(evidenceID: String, state: EvidenceState) {
        precondition(!evidenceID.isEmpty)
        self.evidenceID = evidenceID
        self.state = state
    }
}

public enum ProfileCapability: String, Hashable, Sendable, CaseIterable {
    case recognize
    case instance
    case discover
    case authenticate
    case supports
    case sign
}

public struct CapabilityGate: Sendable {
    private let requirements: [ProfileCapability: [EvidenceRequirement]]

    public init(requirements: [ProfileCapability: [EvidenceRequirement]]) {
        self.requirements = requirements
    }

    public func requirements(for capability: ProfileCapability) -> [EvidenceRequirement] {
        requirements[capability] ?? []
    }

    public func isEnabled(_ capability: ProfileCapability) -> Bool {
        let required = requirements(for: capability)
        return !required.isEmpty && required.allSatisfy(\.state.enablesCapability)
    }
}

public struct ProfileLimits: Sendable, Equatable {
    public let maximumCommandLength: Int
    public let maximumResponseLength: Int
    public let maximumDirectoryLength: Int
    public let maximumCertificateLength: Int

    public init(
        maximumCommandLength: Int,
        maximumResponseLength: Int,
        maximumDirectoryLength: Int,
        maximumCertificateLength: Int
    ) {
        precondition(maximumCommandLength > 0)
        precondition(maximumResponseLength > 0)
        precondition(maximumDirectoryLength > 0)
        precondition(maximumCertificateLength > 0)
        self.maximumCommandLength = maximumCommandLength
        self.maximumResponseLength = maximumResponseLength
        self.maximumDirectoryLength = maximumDirectoryLength
        self.maximumCertificateLength = maximumCertificateLength
    }
}

public struct CardProfileDescriptor: Sendable {
    public let profileID: String
    public let version: ProfileVersion
    public let applicationSelector: Data
    public let capabilityGate: CapabilityGate
    public let limits: ProfileLimits

    public init(
        profileID: String,
        version: ProfileVersion,
        applicationSelector: Data,
        capabilityGate: CapabilityGate,
        limits: ProfileLimits
    ) {
        precondition(!profileID.isEmpty)
        precondition(!applicationSelector.isEmpty)
        self.profileID = profileID
        self.version = version
        self.applicationSelector = applicationSelector
        self.capabilityGate = capabilityGate
        self.limits = limits
    }
}

public protocol CardProfile: Sendable {
    var descriptor: CardProfileDescriptor { get }
    func recognizes(selectedApplication: Data) -> Bool
}

/// Optional public-catalog surface for profiles with independently proven discovery.
/// A registry can use the selected conformer without assuming a DNIe-specific type.
public protocol PublicCatalogCardProfile: CardProfile {
    func makePublicCatalog(instanceID: Data) -> TokenCatalogBuildResult
}

public extension CardProfile {
    func isEnabled(_ capability: ProfileCapability) -> Bool {
        descriptor.capabilityGate.isEnabled(capability)
    }

    func recognizes(selectedApplication: Data) -> Bool {
        isEnabled(.recognize) && selectedApplication == descriptor.applicationSelector
    }
}
