// swift-tools-version:5.9
// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
//
// Swift Package wrapping the `sng-mobile-sdk` UniFFI bindings for iOS.
//
// The package has two targets:
//
//   * `sng_mobile_sdkFFI` — a `binaryTarget` pointing at the
//     `sng_mobile_sdkFFI.xcframework`. The XCFramework bundles the
//     per-arch static archives (`libsng_mobile_sdk.a` for the iOS
//     device + simulator slices) together with the generated C
//     header + module map, so the FFI module name a consumer imports
//     is `sng_mobile_sdkFFI`.
//   * `ShieldNetMobile` — the Swift surface. It contains the
//     UniFFI-generated `sng_mobile_sdk.swift` (which `import`s the
//     `sng_mobile_sdkFFI` module above) plus any hand-written Swift
//     conveniences under `Sources/ShieldNetMobile/`.
//
// The XCFramework and the generated Swift are *build artifacts*: they
// are produced by `scripts/build-xcframework.sh` (which drives the
// repo's `bindings/generate.sh` + `xcodebuild -create-xcframework`)
// and are git-ignored. Run that script once before resolving the
// package locally; CI builds and uploads the XCFramework as an
// artifact. See `apple/README.md`.

import PackageDescription

let package = Package(
    name: "ShieldNetMobile",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "ShieldNetMobile",
            targets: ["ShieldNetMobile"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "sng_mobile_sdkFFI",
            path: "Frameworks/sng_mobile_sdkFFI.xcframework"
        ),
        .target(
            name: "ShieldNetMobile",
            dependencies: ["sng_mobile_sdkFFI"],
            path: "Sources/ShieldNetMobile"
        ),
    ]
)
