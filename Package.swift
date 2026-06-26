// swift-tools-version:5.9
import PackageDescription

// The Swift implementation lives under `swift/` in this multi-language repo.
// Keeping the manifest at the repo root makes the package consumable via
// `.package(url: "https://github.com/Searxly/bulwark.git", from: "0.2.0")`.
let package = Package(
    name: "Bulwark",
    platforms: [.macOS(.v12), .iOS(.v15), .tvOS(.v15), .watchOS(.v8)],
    products: [
        .library(name: "Bulwark", targets: ["Bulwark"]),
    ],
    targets: [
        .target(name: "Bulwark", path: "swift/Sources/Bulwark"),
        .testTarget(name: "BulwarkTests", dependencies: ["Bulwark"], path: "swift/Tests/BulwarkTests"),
    ]
)
