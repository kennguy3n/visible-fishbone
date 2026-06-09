// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
//
// Android library (.aar) module for `sng-mobile-sdk`.
//
// The AAR bundles:
//   * the UniFFI-generated Kotlin (`uniffi.sng_mobile_sdk`), copied
//     into `src/main/kotlin/` by `scripts/build-aar.sh`;
//   * the per-ABI native libraries (`libsng_mobile_sdk.so`), built
//     with `cargo-ndk` into `src/main/jniLibs/` by the same script;
//   * the JNA runtime the generated Kotlin loads the native library
//     through.
//
// Both the generated Kotlin and the `.so`s are git-ignored build
// artifacts; run `scripts/build-aar.sh` (or the CI job) before
// assembling. See `android/README.md`.

plugins {
    id("com.android.library") version "8.6.1"
    id("org.jetbrains.kotlin.android") version "2.0.20"
}

android {
    namespace = "com.shieldnet.mobile"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        // Ship only the ABIs the native build produces; keeps the
        // AAR free of stale slices if a target is added/removed.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        jvmToolchain(17)
    }

    // The generated Kotlin and the cargo-ndk output live outside the
    // AGP defaults; wire both source roots in explicitly.
    sourceSets {
        getByName("main") {
            kotlin.srcDir("src/main/kotlin")
            jniLibs.srcDir("src/main/jniLibs")
        }
    }
}

dependencies {
    // The generated Kotlin loads the native library through JNA; the
    // `@aar` artifact carries JNA's own native bits per ABI.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // The exported async (`suspend`) functions route through
    // kotlinx-coroutines, which the generated bindings import.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
}
