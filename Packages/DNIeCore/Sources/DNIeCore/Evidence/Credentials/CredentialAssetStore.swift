import Foundation

public enum CredentialAssetError: Error, Sendable, Equatable {
    case unavailable
    case invalidFile
}

public enum CredentialAssetStore {
    public static func loadBundledGeneration2() throws -> VerifiedCredentialSet {
        let bundle = Bundle.module
        let candidates = [
            bundle.url(
                forResource: "generation2",
                withExtension: "json",
                subdirectory: "Assets"
            ),
            bundle.url(
                forResource: "generation2",
                withExtension: "json",
                subdirectory: "Evidence/Credentials/Assets"
            ),
            bundle.url(forResource: "generation2", withExtension: "json"),
        ]
        guard let url = candidates.compactMap({ $0 }).first else {
            throw CredentialAssetError.unavailable
        }
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true,
              let size = values.fileSize,
              (1...65_536).contains(size) else {
            throw CredentialAssetError.invalidFile
        }
        let encoded = try Data(contentsOf: url, options: [.mappedIfSafe])
        return try CredentialFixtureVerifier.verifyGeneration2(encoded)
    }
}
