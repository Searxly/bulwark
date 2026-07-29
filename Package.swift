// swift-tools-version:5.9
import PackageDescription

// The Swift implementation lives under `swift/` in this multi-language repo.
// Keeping the manifest at the repo root makes the package consumable via
// `.package(url: "https://github.com/Myrhex-x/bulwark.git", from: "0.2.0")`.
let package = Package(
    name: "Bulwark",
    platforms: [.macOS(.v12), .iOS(.v15), .tvOS(.v15), .watchOS(.v8)],
    products: [
        .library(name: "Bulwark", targets: ["Bulwark"]),
        // Grades the shared corpus and prints one JSON verdict per line, so
        // tools/conformance.py can diff Swift against Python and TypeScript.
        // Not part of the library — consumers depending on the package product
        // above never build it.
        .executable(name: "bulwark-conformance", targets: ["BulwarkConformance"]),
    ],
    targets: [
        .target(name: "Bulwark", path: "swift/Sources/Bulwark"),
        .executableTarget(name: "BulwarkConformance", dependencies: ["Bulwark"],
                          path: "swift/Sources/BulwarkConformance"),
        .testTarget(name: "BulwarkTests", dependencies: ["Bulwark"], path: "swift/Tests/BulwarkTests"),
    ]
)
