# Sentinel Scan (Android)

A native Android port of the sentinel-scan CLI: on-device signature +
heuristic malware scanning with quarantine, restore, and permanent delete.

## Detection

Same detection logic as the CLI (`../src`), ported to Kotlin:

- **Signature hash matching** — SHA-256/MD5 against `app/src/main/assets/signatures.json`.
- **Signature pattern matching** — regex rules for obfuscated PowerShell, PHP
  webshells, LOLBin downloaders, ransom-note language, embedded PE headers.
- **Heuristics** — content/extension mismatch via magic-byte sniffing,
  double-extension masquerade, macro-enabled Office documents, entropy checks.

## Scanning scope

Two ways to pick what gets scanned, both wired into `MainActivity`:

1. **Choose folder to scan** — a Storage Access Framework folder picker.
   Requires no special permission; the app can read, and with the
   persisted write grant, delete/recreate files inside the chosen tree.
2. **Grant full-device access** — requests the `MANAGE_EXTERNAL_STORAGE`
   ("All files access") permission via system settings, then scans
   `Environment.getExternalStorageDirectory()` directly.

`ScanNode` (`app/src/main/java/com/sentinelscan/app/ScanNode.kt`) abstracts
over both so `ScanEngine` only has to walk one kind of tree.

## Quarantine

Quarantined files are copied into app-private internal storage (already
sandboxed by Android from every other app) with a JSON manifest recording
enough to restore them: node type (SAF vs. raw file), the original parent
folder's identity, and the display name. `restore` recreates the file in
its original parent (renamed if that name exists again); `purge` deletes
it for good. See `QuarantineManager.kt`.

## Building

This sandbox has no Android SDK available (network policy blocks
`dl.google.com`), so the APK is built in CI —
`.github/workflows/android-build.yml` assembles a debug APK on every push
that touches `android/**` and publishes it as both a workflow artifact and
a GitHub Release asset.

To build locally with Android Studio or the SDK installed:

```sh
cd android
./gradlew assembleDebug
# APK at app/build/outputs/apk/debug/app-debug.apk
```

Requires JDK 17, Android SDK platform 34, and build-tools 34.0.0 (the
Gradle wrapper handles the Gradle version itself).
