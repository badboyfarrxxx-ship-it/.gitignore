# sentinel-scan

A dependency-free Node.js CLI for scanning files/directories for malware,
with built-in remediation (quarantine, restore, permanent removal).

Detection combines three techniques:

- **Signature (hash) matching** — SHA-256/MD5 of file contents against a
  local database of known-bad hashes (`data/signatures.json`).
- **Signature (pattern) matching** — regex rules for common malicious
  indicators embedded in text/scripts (obfuscated PowerShell, PHP webshell
  `eval()` chains, living-off-the-land downloaders like `certutil`/`mshta`,
  ransom-note language, a smuggled PE header encoded as base64, etc).
- **Heuristics** — content/extension mismatches (e.g. an executable
  disguised with a `.pdf` extension via magic-byte sniffing), double
  extensions (`invoice.pdf.exe`), macro-enabled Office documents, and
  Shannon-entropy checks for packed/obfuscated executables.

This is a local file scanner, not a replacement for a production endpoint
security product — it has no real-time/kernel-level protection and its
bundled signature database is intentionally small (it ships with the
industry-standard [EICAR test file](https://www.eicar.org/) as a safe,
verifiable detection you can test with). Extend `data/signatures.json` or
merge in your own feed with `update-db` to add real threat intelligence.

## Install

```sh
npm install
```

Requires Node.js >= 18 (uses the built-in `node:test` runner and no
third-party dependencies).

## Usage

```sh
# Scan a file or directory
node bin/cli.js scan /path/to/scan

# Same, but machine-readable output for scripting/CI
node bin/cli.js scan /path/to/scan --json

# Scan AND automatically quarantine everything found
node bin/cli.js scan /path/to/scan --fix

# Manually quarantine one specific file
node bin/cli.js quarantine /path/to/file

# List what's currently quarantined
node bin/cli.js list-quarantine

# Put a quarantined file back where it came from
node bin/cli.js restore <id>

# Permanently delete a quarantined item (cannot be undone)
node bin/cli.js purge <id>

# Permanently delete a file directly, bypassing quarantine (requires --force)
node bin/cli.js remove /path/to/file --force

# Merge additional signatures into the database
node bin/cli.js update-db my-feed.json
```

If you install it globally / link it, the same commands are available as
`sentinel-scan scan ...` (see the `bin` field in `package.json`).

### Scan options

| Flag | Description |
| --- | --- |
| `--db <path>` | Use an alternate signature database file |
| `--json` | Print a JSON report instead of text |
| `--fix` | Auto-quarantine every threat found in this run |
| `--quarantine-dir <dir>` | Quarantine location (default `./.quarantine`) |
| `--max-file-mb <n>` | Skip files larger than `n` MB (default 50) |
| `--exclude <name>` | Additional directory name to skip (repeatable) |

### Exit codes

`0` clean or all threats fixed · `1` threats found and not fixed · `2` usage/runtime error — suitable for CI gating.

## How quarantine works

A quarantined file is copied into the quarantine directory (named
`<id>_<original-basename>.quarantined`), has all permissions stripped
(`chmod 000`) so it can't be executed or opened by accident, and the
original is deleted. A `manifest.json` in the quarantine directory records
the original path, hashes, and what was detected, so `restore` can put it
back exactly where it came from (or alongside it, timestamped, if that path
is occupied again) and `purge` can delete it for good.

## Testing

```sh
npm test
```

Runs the full suite (signature matching, heuristics, the scan engine,
quarantine/restore/purge, and CLI end-to-end tests) with Node's built-in
test runner — including a real scan of the EICAR test string so detection
is verified against genuine, safe-to-use antivirus test content rather than
mocked data.

## Project layout

```
bin/cli.js          CLI entrypoint and argument parsing
src/scanEngine.js    Walks files, applies signatures + heuristics
src/signatureDb.js   Loads/matches the hash + pattern signature database
src/heuristics.js    Entropy, magic-byte, extension-based heuristics
src/quarantine.js    Quarantine / restore / purge / remove
src/fileUtils.js     Directory walking, hashing, capped file reads
src/report.js        Text/JSON report formatting
data/signatures.json Bundled signature database
test/                node:test suite
```
