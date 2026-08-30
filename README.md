# ShieldScan

An Android app that scans installed apps and files on-device for malware, using
SHA-256 signature matching plus heuristics — entirely offline.

## What it does

**Scan installed apps** — hashes every installed app's APK and checks it against a
signature database; scores every non-system app on its requested permissions
(accessibility + overlay combos, device admin, SMS/notification access, etc.),
whether it was sideloaded, and other patterns common in Android malware families
(banking trojans, spyware, ransomware/lockware).

**Scan a folder** — pick any folder (e.g. Downloads) via the system file picker;
recursively hashes every file, checks it against the signature database, and flags
disguised double extensions (`invoice.pdf.exe`), executable/script file types, and
high-entropy content (a sign of packing/encryption/obfuscation).

**Scan history** — every scan and its findings are saved locally (Room/SQLite) so
you can review past results.

**Signature database** — ships with the industry-standard EICAR test signature.
Import your own SHA-256 hash feed (JSON or CSV) from a threat-intel source you
trust under Settings — the app has no `INTERNET` permission and never fetches or
uploads anything on its own.

## Why it's not a "real" antivirus

Android sandboxes apps from each other, so no third-party app can arbitrarily
inspect another app's private data or memory the way a desktop AV can. ShieldScan
works within that model: exact-hash signature matching (reliable, but only catches
known threats) plus heuristics on permissions/metadata/entropy (catches patterns,
not proof). Treat a flagged item as a signal to investigate — check the app's
permissions in Settings, look up its package name, or verify the file's hash on a
service like VirusTotal — before uninstalling or deleting anything.

## Architecture

```
app/src/main/java/com/shieldscan/app/
├── data/
│   ├── model/       Domain models: Finding (App/File), RiskLevel, ScanSummary, ThreatSignature
│   ├── signature/   SignatureRepository — loads bundled + imported SHA-256 signatures
│   │                and the dangerous-permission weight table, all from local JSON
│   └── db/          Room database for scan history (ScanRecordEntity, FindingEntity)
├── scanner/
│   ├── PackageScanner.kt     Enumerates installed apps, hashes APKs, applies heuristics
│   ├── FileScanner.kt        Walks a SAF-picked folder, hashes files, applies heuristics
│   └── HeuristicsEngine.kt   Pure scoring functions (no Android dependency)
├── util/HashUtils.kt         Single-pass SHA-256 + Shannon entropy over a stream
└── ui/                       Jetpack Compose screens (Home, Results, History, Settings)
    + Navigation-Compose graph, Material3 theme
```

- **No dangerous storage permissions.** File scanning uses the Storage Access
  Framework (`ACTION_OPEN_DOCUMENT_TREE`), so the user grants access to one folder
  at a time instead of the app requesting broad storage access.
- **`QUERY_ALL_PACKAGES`** is required to enumerate every installed app (Android's
  package-visibility rules otherwise hide most apps from each other) — a
  documented, Play-Store-accepted use case for security tools.
- **Fully offline.** No `INTERNET` permission is requested; signature updates are
  a manual, explicit user action (import a file), never a background fetch.

## Building

Requires Android Studio (or the Android SDK + a JDK 17) — this environment's
sandbox doesn't have the Android SDK installed, so the project could not be
compiled end-to-end here. The Gradle wrapper is included and pinned to Gradle
8.14.3 / AGP 8.7.2 / Kotlin 2.1.0.

```
./gradlew assembleDebug   # build the debug APK
./gradlew test            # run JVM unit tests (heuristics, hashing, risk levels)
```

All pure-logic code (`HashUtils`, `HeuristicsEngine`, `RiskLevel`) was compiled
and unit-tested standalone on the JVM during development to verify correctness
ahead of a full Android build.

## Signature database format

`app/src/main/assets/signatures/malware_hashes.json`:

```json
{
  "signatures": [
    { "sha256": "...", "name": "...", "category": "...", "severity": "...", "source": "..." }
  ]
}
```

Imports (Settings → Import signature feed) accept that same JSON shape, a bare
JSON array of the same objects, or a plain CSV/newline list of `sha256[,name]`
per line — the common export shape of most public hash feeds.

## Disclaimer

ShieldScan is a defensive aid, not a certified antivirus product. Heuristic
findings are signals to review, not guaranteed verdicts — false positives and
false negatives are both possible.
