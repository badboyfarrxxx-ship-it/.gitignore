'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_DB_PATH = path.join(__dirname, '..', 'data', 'signatures.json');

/**
 * Loads and validates a signature database from disk, compiling regex
 * patterns once so repeated scans don't re-parse them per file.
 */
function loadSignatureDb(dbPath = DEFAULT_DB_PATH) {
  const raw = fs.readFileSync(dbPath, 'utf8');
  const db = JSON.parse(raw);

  if (!Array.isArray(db.hashes) || !Array.isArray(db.patterns)) {
    throw new Error(`Invalid signature database at ${dbPath}: expected "hashes" and "patterns" arrays`);
  }

  const hashesBySha256 = new Map();
  const hashesByMd5 = new Map();
  for (const entry of db.hashes) {
    if (entry.sha256) hashesBySha256.set(entry.sha256.toLowerCase(), entry);
    if (entry.md5) hashesByMd5.set(entry.md5.toLowerCase(), entry);
  }

  const compiledPatterns = db.patterns.map((p) => ({
    ...p,
    compiled: new RegExp(p.regex, p.flags || ''),
  }));

  return {
    version: db.version,
    updated: db.updated,
    path: dbPath,
    hashesBySha256,
    hashesByMd5,
    patterns: compiledPatterns,
    hashCount: db.hashes.length,
    patternCount: db.patterns.length,
  };
}

/** Returns the matching hash-signature entry, or null. */
function matchHash(db, { sha256, md5 }) {
  if (sha256 && db.hashesBySha256.has(sha256.toLowerCase())) {
    return db.hashesBySha256.get(sha256.toLowerCase());
  }
  if (md5 && db.hashesByMd5.has(md5.toLowerCase())) {
    return db.hashesByMd5.get(md5.toLowerCase());
  }
  return null;
}

/** Returns all pattern signatures whose regex matches the given text content. */
function matchPatterns(db, content) {
  const matches = [];
  for (const pattern of db.patterns) {
    pattern.compiled.lastIndex = 0;
    if (pattern.compiled.test(content)) {
      matches.push(pattern);
    }
  }
  return matches;
}

/**
 * Merges a feed file's hashes/patterns into an existing database file and
 * writes the result back, deduplicating by sha256 (hashes) and id (patterns).
 */
function updateSignatureDb(dbPath, feedPath) {
  const db = JSON.parse(fs.readFileSync(dbPath, 'utf8'));
  const feed = JSON.parse(fs.readFileSync(feedPath, 'utf8'));

  const existingSha256 = new Set(db.hashes.map((h) => h.sha256 && h.sha256.toLowerCase()));
  const existingPatternIds = new Set(db.patterns.map((p) => p.id));

  let addedHashes = 0;
  let addedPatterns = 0;

  for (const h of feed.hashes || []) {
    const key = h.sha256 && h.sha256.toLowerCase();
    if (key && !existingSha256.has(key)) {
      db.hashes.push(h);
      existingSha256.add(key);
      addedHashes += 1;
    }
  }

  for (const p of feed.patterns || []) {
    if (p.id && !existingPatternIds.has(p.id)) {
      db.patterns.push(p);
      existingPatternIds.add(p.id);
      addedPatterns += 1;
    }
  }

  db.updated = new Date().toISOString().slice(0, 10);
  fs.writeFileSync(dbPath, JSON.stringify(db, null, 2) + '\n');

  return { addedHashes, addedPatterns, totalHashes: db.hashes.length, totalPatterns: db.patterns.length };
}

module.exports = { DEFAULT_DB_PATH, loadSignatureDb, matchHash, matchPatterns, updateSignatureDb };
