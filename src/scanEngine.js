'use strict';

const fs = require('fs');
const path = require('path');

const { loadSignatureDb, matchHash, matchPatterns, DEFAULT_DB_PATH } = require('./signatureDb');
const { runHeuristics } = require('./heuristics');
const { hashBuffer, walk, readFileCapped, DEFAULT_EXCLUDES } = require('./fileUtils');

const DEFAULT_MAX_FILE_BYTES = 50 * 1024 * 1024; // 50MB

const SEVERITY_RANK = { high: 3, medium: 2, low: 1 };

/** Highest-ranked severity across a list of findings. */
function worstSeverity(findings) {
  return findings.reduce(
    (worst, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst] ? f.severity : worst),
    'low'
  );
}

/**
 * Scans a single file's buffer against the signature DB and heuristics.
 * Returns null if the file is clean.
 */
function scanBuffer(filePath, buffer, db) {
  const detections = [];
  const { sha256, md5 } = hashBuffer(buffer);

  const hashHit = matchHash(db, { sha256, md5 });
  if (hashHit) {
    detections.push({
      id: hashHit.id,
      name: hashHit.name,
      severity: hashHit.severity,
      description: hashHit.description,
      source: 'signature-hash',
    });
  }

  // Pattern matching only makes sense on text-ish content; still safe to run
  // against binary buffers since regexes are anchored to specific byte/text
  // sequences, but skip huge buffers converted to string to bound memory/CPU.
  if (buffer.length <= 10 * 1024 * 1024) {
    const text = buffer.toString('latin1');
    for (const pattern of matchPatterns(db, text)) {
      detections.push({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        source: 'signature-pattern',
      });
    }
  }

  for (const heur of runHeuristics(filePath, buffer)) {
    detections.push({ ...heur, source: 'heuristic' });
  }

  if (detections.length === 0) return null;

  return {
    filePath,
    sha256,
    md5,
    size: buffer.length,
    severity: worstSeverity(detections),
    detections,
  };
}

/**
 * Recursively scans `target` (a file or directory).
 * options: { dbPath, maxFileBytes, excludes, onProgress(filePath) }
 */
function scan(target, options = {}) {
  const {
    dbPath = DEFAULT_DB_PATH,
    maxFileBytes = DEFAULT_MAX_FILE_BYTES,
    excludes = DEFAULT_EXCLUDES,
    onProgress,
  } = options;

  const db = loadSignatureDb(dbPath);
  const startedAt = Date.now();

  const stat = fs.statSync(target);
  const files = stat.isDirectory() ? walk(target, { excludes }) : [target];

  let filesScanned = 0;
  let filesSkipped = 0;
  const threats = [];

  for (const filePath of files) {
    if (onProgress) onProgress(filePath);
    const { buffer, truncated, size } = readFileCapped(filePath, maxFileBytes);
    if (truncated) {
      filesSkipped += 1;
      continue;
    }

    filesScanned += 1;
    let result;
    try {
      result = scanBuffer(filePath, buffer, db);
    } catch (err) {
      filesSkipped += 1;
      filesScanned -= 1;
      continue;
    }
    if (result) threats.push(result);
  }

  return {
    target: path.resolve(target),
    dbVersion: db.version,
    startedAt: new Date(startedAt).toISOString(),
    durationMs: Date.now() - startedAt,
    filesScanned,
    filesSkipped,
    threatsFound: threats.length,
    threats,
  };
}

module.exports = { scan, scanBuffer, worstSeverity, DEFAULT_MAX_FILE_BYTES };
