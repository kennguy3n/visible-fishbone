# ShieldNetMobile — Swift Package

The iOS distribution of [`sng-mobile-sdk`](../README.md): a Swift
Package that wraps the UniFFI-generated Swift surface around an
`XCFramework` of the crate's static library.

## Layout

```text
apple/
  Package.swift                       # SPM manifest (committed)
  Sources/ShieldNetMobile/
    SngMobile.swift                   # hand-written Swift (committed)
    sng_mobile_sdk.swift              # generated (git-ignored)
  Frameworks/
    sng_mobile_sdkFFI.xcframework     # built artifact (git-ignored)
  scripts/build-xcframework.sh        # builds the two above
```

`Package.swift` and the hand-written `SngMobile.swift` are committed.
The generated Swift and the `XCFramework` are **build artifacts**: run
the build script once before resolving the package locally (CI builds
and uploads the `XCFramework` — see
[`.github/workflows/mobile-sdk.yml`](../../../.github/workflows/mobile-sdk.yml)).

## Build (macOS host with Xcode)

```sh
crates/sng-mobile-sdk/apple/scripts/build-xcframework.sh           # release
crates/sng-mobile-sdk/apple/scripts/build-xcframework.sh debug     # or debug
```

The script regenerates the bindings, cross-compiles the `staticlib`
for `aarch64-apple-ios` (device) and a `lipo`-fused
`aarch64-apple-ios-sim` + `x86_64-apple-ios` simulator slice,
assembles `sng_mobile_sdkFFI.xcframework`, and copies the generated
`sng_mobile_sdk.swift` into the package.

## Consume

Point an Xcode project / another package at this directory (or a
tagged release that ships a `binaryTarget` `url` + `checksum`):

```swift
.package(path: "crates/sng-mobile-sdk/apple")
```

```swift
import ShieldNetMobile

let sdk = try MobileSdk(config: config)
sdk.setPowerState(state: .lowPower)   // stretch the heartbeat 4× on battery saver
let health = sdk.health()
```

The FFI module is imported by the generated Swift as
`sng_mobile_sdkFFI`; consumers only `import ShieldNetMobile`.
