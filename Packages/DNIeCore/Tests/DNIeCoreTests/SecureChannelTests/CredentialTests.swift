import Foundation
import XCTest
@testable import DNIeCore

final class CredentialTests: XCTestCase {
    func testRecordedGeneration2ProvenanceMatchesADR008IntegrityGate() {
        let metadata = CredentialProvenanceMetadata.generation2

        XCTAssertEqual(metadata.fixtureVersion, 2)
        XCTAssertEqual(metadata.setID, "generation_2")
        XCTAssertEqual(
            metadata.manifestSHA256,
            "3bac8e7a79c62ee35b9ba7b47e3d3fbbb4d16a6461cb89f59f744f55652fff6d"
        )
        XCTAssertEqual(
            metadata.sourceSHA256,
            "6528a9662523362f53479440c6611a241cda1940a2b5a05fa5deb4c8bf3cba4a"
        )
        XCTAssertEqual(
            metadata.officialDistributionSHA256,
            "d2de4308190433a22683ef7fa85637b446f2a9420e35e50b86314a5590c46bc2"
        )
        XCTAssertEqual(metadata.orderedFieldNames.count, 18)
        XCTAssertEqual(Set(metadata.orderedFieldNames).count, 18)
        XCTAssertTrue(metadata.requiredPrivateKeyRoles == [.user, .pin])
    }

    func testUnknownAndAmbiguousHierarchySelectionsFailClosed() throws {
        XCTAssertEqual(
            try CredentialGenerationSelector.select(
                historicalIssuerMatch: false,
                generation2IssuerMatch: true
            ),
            .generation2
        )
        XCTAssertThrowsError(
            try CredentialGenerationSelector.select(
                historicalIssuerMatch: false,
                generation2IssuerMatch: false
            )
        ) { XCTAssertEqual($0 as? CredentialFixtureError, .unsupportedGeneration) }
        XCTAssertThrowsError(
            try CredentialGenerationSelector.select(
                historicalIssuerMatch: true,
                generation2IssuerMatch: true
            )
        ) { XCTAssertEqual($0 as? CredentialFixtureError, .ambiguousGeneration) }
        XCTAssertThrowsError(
            try CredentialGenerationSelector.select(
                historicalIssuerMatch: true,
                generation2IssuerMatch: false
            )
        ) { XCTAssertEqual($0 as? CredentialFixtureError, .unsupportedGeneration) }
    }

    func testAuthorizedLocalFixturePassesManifestAndPrivateKeyBinding() throws {
        let encoded = try localFixtureDataOrSkip()

        let verified = try CredentialFixtureVerifier.verifyGeneration2(encoded)

        XCTAssertEqual(verified.generation, .generation2)
        XCTAssertEqual(
            verified.fieldNames,
            CredentialProvenanceMetadata.generation2.orderedFieldNames
        )
        XCTAssertEqual(verified.privateKeyRoles, [.user, .pin])
    }

    func testStagedProductionAssetUsesTheSameFailClosedVerifier() throws {
        let verified: VerifiedCredentialSet
        do {
            verified = try CredentialAssetStore.loadBundledGeneration2()
        } catch CredentialAssetError.unavailable {
            throw XCTSkip("ADR-008 local production asset is intentionally unavailable")
        }

        XCTAssertEqual(verified.generation, .generation2)
        XCTAssertEqual(
            verified.fieldNames,
            CredentialProvenanceMetadata.generation2.orderedFieldNames
        )
        XCTAssertEqual(verified.privateKeyRoles, [.user, .pin])
    }

    func testTamperedCredentialFieldFailsManifestBeforeUse() throws {
        let encoded = try localFixtureDataOrSkip()
        let tampered = try mutateFixture(encoded) { root in
            var fields = try XCTUnwrap(root["fields_hex"] as? [String: Any])
            let name = CredentialProvenanceMetadata.generation2.orderedFieldNames[0]
            var value = try XCTUnwrap(fields[name] as? String)
            let replacement = value.first == "0" ? "1" : "0"
            value.replaceSubrange(value.startIndex...value.startIndex, with: replacement)
            fields[name] = value
            root["fields_hex"] = fields
        }

        XCTAssertThrowsError(try CredentialFixtureVerifier.verifyGeneration2(tampered)) {
            XCTAssertEqual($0 as? CredentialFixtureError, .manifestMismatch)
        }
    }

    func testUnknownSetAndMetadataMismatchFailBeforeCredentialUse() throws {
        let encoded = try localFixtureDataOrSkip()
        let unknown = try mutateFixture(encoded) { $0["set_id"] = "generation_unknown" }
        XCTAssertThrowsError(try CredentialFixtureVerifier.verifyGeneration2(unknown)) {
            XCTAssertEqual($0 as? CredentialFixtureError, .unsupportedGeneration)
        }

        let mismatched = try mutateFixture(encoded) {
            $0["official_binary_sha256"] = String(repeating: "0", count: 64)
        }
        XCTAssertThrowsError(try CredentialFixtureVerifier.verifyGeneration2(mismatched)) {
            XCTAssertEqual($0 as? CredentialFixtureError, .provenanceMismatch)
        }
    }

    private func localFixtureDataOrSkip() throws -> Data {
        let url = repositoryRoot().appendingPathComponent(
            "Validation/private/SecureChannel/generation2.json"
        )
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip("ADR-008 local credential fixture is intentionally unavailable")
        }
        return try Data(contentsOf: url, options: [.mappedIfSafe])
    }

    private func mutateFixture(
        _ encoded: Data,
        mutation: (inout [String: Any]) throws -> Void
    ) throws -> Data {
        var root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        )
        try mutation(&root)
        return try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
    }

    private func repositoryRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
