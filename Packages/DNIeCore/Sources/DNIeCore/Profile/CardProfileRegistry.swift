import Foundation

/// Selects one evidence-enabled profile for an exact application selector.
/// The registry is independent of readers and platform token construction.
public struct CardProfileRegistry: Sendable {
    private let profiles: [any CardProfile]

    public init(profiles: [any CardProfile]) {
        self.profiles = profiles
    }

    public func profile(for selectedApplication: Data) -> (any CardProfile)? {
        var match: (any CardProfile)?
        for candidate in profiles {
            guard candidate.isEnabled(.recognize),
                  candidate.descriptor.applicationSelector == selectedApplication,
                  candidate.recognizes(selectedApplication: selectedApplication) else {
                continue
            }
            guard match == nil else { return nil }
            match = candidate
        }
        return match
    }

    public func publicCatalog(
        for selectedApplication: Data,
        instanceID: Data
    ) -> TokenCatalogBuildResult? {
        guard !instanceID.isEmpty,
              let selected = profile(for: selectedApplication),
              selected.isEnabled(.instance), selected.isEnabled(.discover),
              let provider = selected as? any PublicCatalogCardProfile else {
            return nil
        }
        return provider.makePublicCatalog(instanceID: instanceID)
    }
}
