// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "DNIeCore",
    platforms: [
        .macOS(.v26),
    ],
    products: [
        .library(name: "DNIeCore", targets: ["DNIeCore"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "DNIeCore",
            resources: [
                .copy("Evidence/Credentials/Assets"),
            ],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedLibrary("z"),
            ]
        ),
        .testTarget(
            name: "DNIeCoreTests",
            dependencies: ["DNIeCore"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
