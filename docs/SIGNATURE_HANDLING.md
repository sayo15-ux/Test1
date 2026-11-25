# Signature handling in DEX Protection

This document records what is actually implemented in this project. It
distinguishes static DEX Signature Kill from the separate SigFall-style
runtime interceptor that this project now provides as an Xposed/LSPosed module.

## 1. Existing code found during analysis

- `Signing.sign()` already used `com.android.tools.build:apksig:8.9.2` to sign
  output (v1/v2/v3; v4 is explicitly disabled) and to verify the freshly
  signed output with `ApkVerifier`.
- `Signing.certificateDigest()` hashed the *chosen signing identity*, for
  display only.
- There was **no** user-facing APK signature test screen.
- The drawer item "Tools" was a no-op.
- Signature Killer was added as native mode `3` (see below).

## 2. Test Signature (implemented)

`SignatureInspector.java` calls `ApkVerifier.Builder(file).build().verify()`
from the already-present apksig dependency. No new library is required.

It reports only values apksig produced:

- overall verification verdict for the checked Android platform range;
- v1 (JAR), v2, v3, v3.1 and v4 schemes as **present** vs **verified**, with
  signer counts. v4 is verified when a sibling `<apk>.idsig` sidecar exists and
  is readable; otherwise it is reported as not present with that reason;
- signer certificate subject, issuer, serial, validity period and public key;
- SHA-1 and SHA-256 fingerprints of the certificate (`getEncoded()`), which is
  the same identity Android/MT Manager display;
- source-stamp presence/verification, plus apksig errors and warnings.

**Certificate identity is not APK integrity.** The screen says this explicitly:
a fingerprint identifies the signing key and is identical across builds signed
with the same key. Integrity is only established when the schemes verify for
the file being inspected. A file modified after signing keeps the same
certificate but fails verification.

Unsigned, empty, missing and malformed files are handled without exceptions
escaping the inspector: they produce a "No signature found" or "Malformed APK"
result with a reason. The result is computed on the app's worker executor and
posted back to the main thread, so the UI never blocks.

This is an *inspector*, not NP Manager's "test signing strength" workflow,
which repeatedly re-signs and launches an app to see which configuration it
accepts. That workflow requires installing apps and is not implemented.

## 3. Signature Kill (implemented, static only)

`signature.cpp` rewrites DEX method bodies before the normal signing step. It
targets in-app checks that call:

- `PackageManager.getPackageInfo` / `getPackageArchiveInfo` with
  `GET_SIGNATURES` or `GET_SIGNING_CERTIFICATES`;
- `PackageInfo.signatures` / `PackageInfo.signingInfo`;
- `Signature.*` and `SigningInfo.*`;
- supporting comparisons via `MessageDigest`, `Arrays.equals` and
  `X509Certificate`.

Detected methods are replaced with a return stub (`true` for boolean, `0` for
numeric, `null` for objects); constructors and `<clinit>` are left alone.
The APK is then signed by the existing pipeline and verified again. A success
claim is only made when the native report counts patched methods and the
output verification succeeds.

**Installation verification vs runtime verification.** Android's installer
verifies v1/v2/v3 signatures over the whole APK when it installs it; that is
`ApkVerifier`'s job and the output still has a valid signature. Signature Kill
instead tries to change the checks the *running app* performs on itself.
Re-signing with your key changes the certificate; it is not a hook, and a
successful re-sign is not reported as a bypass by itself.

**Limits.** Reflection, native (`lib*.so`) checks, comparisons hidden behind
custom hash logic, inverted boolean checks and obfuscated call chains are not
detected. Heavily modified apps still need manual DEX review. This static mode
itself has no runtime component, no root requirement and no Xposed/LSPosed
dependency; the optional runtime module in section 4 is a separate feature.

## 4. SigFall-related runtime module (implemented, limited)

Public information about SigFall is limited; it is distributed through
NP Manager rather than as a documented public API. The points below are based
on NP Manager release notes, public usage guides, and the publicly visible
projects of its author (Eirv: `LSPlant`, `android-inline-hook`,
`SimpleIORedirect`, `ElfLoader`, `SigPlus`). Details marked "inferred" are not
verified against source.

- **Hook framework / installation.** SigFall appears as NP Manager's
  "去签" (de-sign) option and as the strongest "fancy" mode in its Test
  Signature feature. Public guides show the injected entry point
  `sigfall.component.SigFallApplication` in the target's `AndroidManifest.xml`,
  i.e. the workflow *modifies the APK before installation* and the injected
  component runs inside the target app afterwards. NP Manager release notes
  mention fixes for running in an Xposed environment, so an Xposed/LSPosed
  installation may also be involved depending on version (inferred).
- **Runtime interception architecture (inferred).** A Java/ART layer would
  intercept `PackageManager.getPackageInfo`/`getPackageArchiveInfo`,
  `PackageInfo.signatures`/`signingInfo`, `Signature`/`SigningInfo` and
  certificate-digest comparisons, returning a spoofed identity. A native layer
  would cover file/path checks such as `openat`/`stat`, consistent with the
  author's inline-hook and seccomp/user-notify I/O-redirect projects. This is
  *runtime* behaviour: it only exists while the patched app is running.
- **Java vs native verification.** Java checks are the ones this project's
  static killer can often patch. Native checks, or checks that read APK bytes
  from disk, need the native interception layer described above and are
  outside the scope of DEX rewriting.
- **Android versions / dependencies.** NP Manager notes reference a SigFall
  version selector and adaptation to Android 17 Beta 3, HarmonyOS and Xposed
  environments. No authoritative compatibility matrix is published. The
  injected payload needs matching native libraries and an ART hooking
  implementation; availability varies by Android version and architecture.
- **On-device vs APK modification.** APK modification: injecting the component,
  changing the manifest entry, adding native libraries, then signing. On
  device: hooking calls and returning the spoofed signature while the app runs.

Because SigFall itself is not publicly available, this project does **not**
claim to ship it. It ships a clearly labelled **SigFall-style runtime
interceptor**, implemented as an Xposed/LSPosed module inside the existing app:

- `assets/xposed_init` plus manifest metadata register `SignatureHook` as a
  real Xposed module entry point (`compileOnly de.robv.android.xposed:api:82`,
  so the framework supplies the API at runtime).
- `SignatureHook` hooks `Application.attach`, then intercepts
  `ApplicationPackageManager.getPackageInfo`,
  `getPackageArchiveInfo`, `PackageInfoFlags` overloads and
  `getPackageInfoAsUser` for the configured target packages. It replaces
  `PackageInfo.signatures` and `signingInfo` with a certificate selected by the
  user.
- `RuntimeHookDialog` (drawer item **Runtime Hook**) manages target packages,
  chooses a signature-source APK, shows Xposed detection and saves/confirms
  the configuration. The first signer's certificate is extracted with the same
  apksig code used by Test Signature, so it is real certificate material, not
  a fake value.
- `HookConfig` stores configuration in SharedPreferences with a synchronous
  commit and makes that preference file readable to hook processes. Hooked
  apps read it through `XSharedPreferences`; the read-only
  `HookConfigProvider` is a fallback for environments where that file is not
  readable.

**Boundaries and honest limitations:** this is not SigFall, does not use
`sigfall.component.SigFallApplication`, does not inject native libraries and
does not modify the target APK. It only changes Java-layer `PackageInfo`
signature responses. It does not bypass native checks, direct APK file reads,
self-integrity checks, reflection-based comparisons or installer signature
verification. Xposed/LSPosed must be installed, this module enabled, target
apps added to its scope, and the target app restarted. The `ContentProvider`
fallback can be blocked by Android
11+ package visibility if the target does not declare this authority; the
`XSharedPreferences` path is primary. No Android 17 or HarmonyOS compatibility
is claimed.

## 5. Signature Kill v4 clean-room experiment

Signature Kill v4 is native mode `6`. Its normal path injects the prebuilt
`fancybypass.component.*` helper DEX and `libfancy-bypass.so` payloads.
The opt-in **Clean-room DEX + native payload** flag (`signature_kill_v4`,
bit `128`) instead uses the self-generated `sigfall.component.SigFallApplication`
and `SigFallAppFactory` classes plus `libsigfall.so` built from `sigfall.cpp`.
It forces embedding of the original APK and patching of APK path fields.

The generated proxy installs a `PackageManager` proxy in `attachBaseContext`,
hooks `getPackageInfo`/`getPackageArchiveInfo`/`generatePackageInfo`, extracts
the original APK to `files/fancy/origin.apk`, and copies the native library to
`files/libsigfall/<abi>.so`. The native layer exempts hidden APIs, patches GOT
entries for file/map functions, filters `/proc/self/maps`, and redirects APK
path reads to the extracted original. Only arm and arm64 payloads are provided.

`patchSignatureDigests()` and the `setSignatureDigest` JNI method remain
available but are not wired into v4; the clean-room flag does not use them.

## 6. Verification status

Build/test tooling (`java`, Gradle wrapper, C++ compiler) is not available in
the environment where these changes were made, so compilation and on-device
testing could not be completed here. Run:

```
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
cd host && make test
```

and inspect a real APK with Test Signature before relying on the results.
