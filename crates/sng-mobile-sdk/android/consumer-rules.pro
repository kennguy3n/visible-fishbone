# Copyright 2026 ShieldNet Gateway contributors.
# SPDX-License-Identifier: LicenseRef-Proprietary
#
# Consumer ProGuard/R8 rules shipped inside the AAR. JNA resolves the
# native FFI declarations reflectively, so the generated UniFFI types
# and JNA's own classes must survive shrinking in the consuming app.

# UniFFI-generated bindings (JNA Library/Structure/Callback subtypes
# are bound by reflection on their field/method names).
-keep class uniffi.sng_mobile_sdk.** { *; }

# JNA runtime.
-keep class com.sun.jna.** { *; }
-keepclassmembers class com.sun.jna.** { *; }
-dontwarn java.awt.**
