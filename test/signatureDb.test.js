'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { loadSignatureDb, matchHash, matchPatterns, DEFAULT_DB_PATH } = require('../src/signatureDb');

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

test('loadSignatureDb loads the bundled database with hashes and patterns', () => {
  const db = loadSignatureDb(DEFAULT_DB_PATH);
  assert.ok(db.hashCount > 0);
  assert.ok(db.patternCount > 0);
});

test('matchHash finds the EICAR test file by its real sha256', () => {
  const db = loadSignatureDb(DEFAULT_DB_PATH);
  const sha256 = crypto.createHash('sha256').update(EICAR).digest('hex');
  const hit = matchHash(db, { sha256 });
  assert.ok(hit);
  assert.equal(hit.id, 'EICAR-STANDARD');
});

test('matchHash returns null for an unknown hash', () => {
  const db = loadSignatureDb(DEFAULT_DB_PATH);
  const hit = matchHash(db, { sha256: 'f'.repeat(64) });
  assert.equal(hit, null);
});

test('matchPatterns detects an embedded EICAR string inside larger content', () => {
  const db = loadSignatureDb(DEFAULT_DB_PATH);
  const content = `some header\n${EICAR}\nsome footer`;
  const hits = matchPatterns(db, content);
  assert.ok(hits.some((h) => h.id === 'EICAR-STRING'));
});

test('matchPatterns detects a PowerShell encoded-command indicator', () => {
  const db = loadSignatureDb(DEFAULT_DB_PATH);
  const content = 'powershell.exe -enc ' + 'A'.repeat(60);
  const hits = matchPatterns(db, content);
  assert.ok(hits.some((h) => h.id === 'PS-ENCODED-CMD'));
});

test('matchPatterns finds nothing in benign content', () => {
  const db = loadSignatureDb(DEFAULT_DB_PATH);
  const hits = matchPatterns(db, 'Just a normal README describing this project.');
  assert.deepEqual(hits, []);
});
