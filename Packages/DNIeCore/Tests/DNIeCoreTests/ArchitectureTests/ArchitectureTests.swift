import Foundation
import XCTest

final class ArchitectureTests: XCTestCase {
    func testCoreSourcesExcludeForbiddenRuntimeDependenciesAndReaderBranches() throws {
        let files = try swiftSourceFiles()
        let forbidden = [
            #"import\s+(AppKit|WebKit|CryptoTokenKit)"#,
            #"\b(PKCS11|PKCS#11|PCSC|winscard|OpenSC)\b"#,
            #"\b(OMNIKEY|vendorID|productID|usbIdentifier)\b"#,
        ]

        for file in files {
            let source = try String(contentsOf: file, encoding: .utf8)
            for pattern in forbidden {
                XCTAssertNil(
                    source.range(of: pattern, options: .regularExpression),
                    "Forbidden dependency or reader branch in \(file.path): \(pattern)"
                )
            }
        }
    }

    func testLayerFilesDoNotReachAcrossOwnedBoundaries() throws {
        let root = sourceRoot()
        let rules: [(String, [String])] = [
            ("Diagnostics", ["CardTransport", "CardProfile"]),
            ("Identity", ["CardTransport", "DiagnosticEvent"]),
            ("Profile", ["DiagnosticEvent", "TokenCoordinator"]),
        ]

        for (directory, forbiddenSymbols) in rules {
            let files = try swiftFiles(under: root.appendingPathComponent(directory))
            for file in files {
                let source = try String(contentsOf: file, encoding: .utf8)
                for symbol in forbiddenSymbols {
                    XCTAssertFalse(
                        source.contains(symbol),
                        "Cross-layer symbol \(symbol) in \(file.path)"
                    )
                }
            }
        }
    }

    private func swiftSourceFiles() throws -> [URL] {
        try swiftFiles(under: sourceRoot())
    }

    private func sourceRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/DNIeCore")
    }

    private func swiftFiles(under root: URL) throws -> [URL] {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isRegularFileKey]
        ) else {
            XCTFail("Cannot enumerate \(root.path)")
            return []
        }
        return enumerator.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
    }
}
