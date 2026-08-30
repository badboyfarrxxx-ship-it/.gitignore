'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_QUARANTINE_DIR = path.join(process.cwd(), '.quarantine');
const MANIFEST_NAME = 'manifest.json';

function manifestPath(quarantineDir) {
  return path.join(quarantineDir, MANIFEST_NAME);
}

function ensureQuarantineDir(quarantineDir) {
  fs.mkdirSync(quarantineDir, { recursive: true });
  const mPath = manifestPath(quarantineDir);
  if (!fs.existsSync(mPath)) {
    fs.writeFileSync(mPath, JSON.stringify({ entries: [] }, null, 2) + '\n');
  }
}

function readManifest(quarantineDir) {
  ensureQuarantineDir(quarantineDir);
  return JSON.parse(fs.readFileSync(manifestPath(quarantineDir), 'utf8'));
}

function writeManifest(quarantineDir, manifest) {
  fs.writeFileSync(manifestPath(quarantineDir), JSON.stringify(manifest, null, 2) + '\n');
}

/**
 * Moves a detected-threat file into the quarantine directory: strips all
 * permissions (so it cannot be executed or opened) and records enough
 * metadata in the manifest to restore it later.
 */
function quarantineFile(scanResult, quarantineDir = DEFAULT_QUARANTINE_DIR) {
  ensureQuarantineDir(quarantineDir);
  const manifest = readManifest(quarantineDir);

  const { filePath, sha256, size, severity, detections } = scanResult;
  const id = crypto.randomBytes(8).toString('hex');
  const storedName = `${id}_${path.basename(filePath)}.quarantined`;
  const storedPath = path.join(quarantineDir, storedName);

  fs.copyFileSync(filePath, storedPath);
  fs.chmodSync(storedPath, 0o000);
  fs.unlinkSync(filePath);

  const entry = {
    id,
    originalPath: path.resolve(filePath),
    storedPath,
    sha256,
    size,
    severity,
    detections,
    quarantinedAt: new Date().toISOString(),
  };
  manifest.entries.push(entry);
  writeManifest(quarantineDir, manifest);

  return entry;
}

/** Permanently deletes a file (no quarantine). Used for direct "remove". */
function removeFile(filePath) {
  fs.unlinkSync(filePath);
}

function listQuarantine(quarantineDir = DEFAULT_QUARANTINE_DIR) {
  return readManifest(quarantineDir).entries;
}

/** Restores a quarantined file to its original location (or a safe fallback if occupied). */
function restoreFile(id, quarantineDir = DEFAULT_QUARANTINE_DIR) {
  const manifest = readManifest(quarantineDir);
  const idx = manifest.entries.findIndex((e) => e.id === id);
  if (idx === -1) throw new Error(`No quarantined item with id "${id}"`);
  const entry = manifest.entries[idx];

  let destination = entry.originalPath;
  if (fs.existsSync(destination)) {
    destination = `${entry.originalPath}.restored-${Date.now()}`;
  }

  fs.chmodSync(entry.storedPath, 0o644);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(entry.storedPath, destination);
  fs.unlinkSync(entry.storedPath);

  manifest.entries.splice(idx, 1);
  writeManifest(quarantineDir, manifest);

  return { ...entry, restoredTo: destination };
}

/** Permanently deletes a quarantined item (cannot be undone). */
function purgeQuarantined(id, quarantineDir = DEFAULT_QUARANTINE_DIR) {
  const manifest = readManifest(quarantineDir);
  const idx = manifest.entries.findIndex((e) => e.id === id);
  if (idx === -1) throw new Error(`No quarantined item with id "${id}"`);
  const entry = manifest.entries[idx];

  fs.chmodSync(entry.storedPath, 0o644);
  fs.unlinkSync(entry.storedPath);
  manifest.entries.splice(idx, 1);
  writeManifest(quarantineDir, manifest);

  return entry;
}

module.exports = {
  DEFAULT_QUARANTINE_DIR,
  quarantineFile,
  removeFile,
  listQuarantine,
  restoreFile,
  purgeQuarantined,
};
