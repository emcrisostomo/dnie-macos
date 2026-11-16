import Foundation
import XCTest

final class ScaffoldTests: XCTestCase {
    func testExtensionUsesOnlyReviewedTemplateAttributes() throws {
        let root = repositoryRoot()
        let plistURL = root.appendingPathComponent("TokenExtension/Info.plist")
        let data = try Data(contentsOf: plistURL)
        let plist = try XCTUnwrap(
            PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        )
        let extensionDictionary = try XCTUnwrap(plist["NSExtension"] as? [String: Any])
        let attributes = try XCTUnwrap(
            extensionDictionary["NSExtensionAttributes"] as? [String: Any]
        )

        XCTAssertEqual(extensionDictionary["NSExtensionPointIdentifier"] as? String, "com.apple.ctk-tokens")
        XCTAssertEqual(attributes["com.apple.ctk.token-type"] as? String, "smartcard")
        XCTAssertEqual(attributes["com.apple.ctk.aid"] as? String, "A000000063504B43532D3135")
        XCTAssertEqual(attributes["com.apple.ctk.class-id"] as? String, "org.dniemacos.dnietoken.token")
        XCTAssertEqual(
            attributes["com.apple.ctk.driver-class"] as? String,
            "DNIeTokenExtension.TokenDriver"
        )
        XCTAssertEqual(
            Set(attributes.keys),
            Set([
                "com.apple.ctk.aid",
                "com.apple.ctk.class-id",
                "com.apple.ctk.driver-class",
                "com.apple.ctk.token-type",
            ])
        )
    }

    func testPrivateOperationDelegateUsesOnlyTheNativeCardPath() throws {
        let sourceDirectory = repositoryRoot().appendingPathComponent("TokenExtension")
        let source = try FileManager.default
            .contentsOfDirectory(at: sourceDirectory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "swift" }
            .map { try String(contentsOf: $0, encoding: .utf8) }
            .joined(separator: "\n")
        XCTAssertTrue(source.contains("supports operation: TKTokenOperation"))
        XCTAssertTrue(source.contains("beginAuthFor operation: TKTokenOperation"))
        XCTAssertTrue(source.contains("sign dataToSign: Data"))
        let forbidden = ["beginSession", "endSession", "SecKeyCreateSignature"]
        for marker in forbidden {
            XCTAssertFalse(source.contains(marker), "Forbidden scaffold capability: \(marker)")
        }
    }

    func testDeliveryHostOnlyTerminatesAfterRegistrationLaunch() throws {
        let sourceURL = repositoryRoot().appendingPathComponent("HostApp/AppDelegate.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)

        XCTAssertTrue(source.contains("NSApp.terminate(nil)"))
        for forbidden in ["TKSmartCard", "SecCertificate", "Safari", "Chrome", "Edge"] {
            XCTAssertFalse(source.contains(forbidden), "Host contains forbidden logic: \(forbidden)")
        }
    }

    private func repositoryRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
