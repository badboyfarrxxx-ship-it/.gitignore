'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_EXCLUDES = new Set(['.git', 'node_modules', '.quarantine']);

/** Computes sha256 + md5 of a buffer. */
function hashBuffer(buffer) {
  return {
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
    md5: crypto.createHash('md5').update(buffer).digest('hex'),
  };
}

/**
 * Recursively yields absolute file paths under `root`, skipping excluded
 * directory names and never following symlinks (avoids symlink loops and
 * escaping the scan root).
 */
function* walk(root, { excludes = DEFAULT_EXCLUDES, maxDepth = Infinity } = {}, depth = 0) {
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch (err) {
    if (err.code === 'EACCES' || err.code === 'ENOENT') return;
    throw err;
  }

  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const fullPath = path.join(root, entry.name);

    if (entry.isDirectory()) {
      if (excludes.has(entry.name)) continue;
      if (depth < maxDepth) yield* walk(fullPath, { excludes, maxDepth }, depth + 1);
    } else if (entry.isFile()) {
      yield fullPath;
    }
  }
}

/** Reads a file, refusing to load more than maxBytes into memory. */
function readFileCapped(filePath, maxBytes) {
  const stat = fs.statSync(filePath);
  if (stat.size > maxBytes) {
    return { buffer: null, truncated: true, size: stat.size };
  }
  return { buffer: fs.readFileSync(filePath), truncated: false, size: stat.size };
}

module.exports = { DEFAULT_EXCLUDES, hashBuffer, walk, readFileCapped };
