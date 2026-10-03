'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { scan, scanBuffer } = require('../src/scanEngine');
const { loadSignatureDb, DEFAULT_DB_PATH } = require('../src/signatureDb');

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-scan-test-'));
}

test('scan: flags the EICAR test file inside a directory', () => {
  const dir = makeTmpDir();
  fs.writeFileSync(path.join(dir, 'eicar.com'), EICAR);
  fs.writeFileSync(path.join(dir, 'clean.txt'), 'nothing to see here');

  const result = scan(dir);
  assert.equal(result.filesScanned, 2);
  assert.equal(result.threatsFound, 1);
  assert.equal(result.threats[0].severity, 'high');
  assert.ok(result.threats[0].detections.some((d) => d.id === 'EICAR-STANDARD'));

  fs.rmSync(dir, { recursive: true, force: true });
});

test('scan: excludes node_modules and .git by default', () => {
  const dir = makeTmpDir();
  fs.mkdirSync(path.join(dir, 'node_modules'));
  fs.writeFileSync(path.join(dir, 'node_modules', 'eicar.com'), EICAR);
  fs.writeFileSync(path.join(dir, 'clean.txt'), 'ok');

  const result = scan(dir);
  assert.equal(result.filesScanned, 1);
  assert.equal(result.threatsFound, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('scan: an empty directory yields a clean report', () => {
  const dir = makeTmpDir();
  const result = scan(dir);
  assert.equal(result.filesScanned, 0);
  assert.equal(result.threatsFound, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('scanBuffer: returns null for content matching nothing', () => {
  const db = loadSignatureDb(DEFAULT_DB_PATH);
  const result = scanBuffer('/tmp/readme.txt', Buffer.from('just some regular text'), db);
  assert.equal(result, null);
});

test('scanBuffer: combines signature and heuristic detections', () => {
  const db = loadSignatureDb(DEFAULT_DB_PATH);
  const result = scanBuffer('invoice.pdf.exe', Buffer.from(EICAR), db);
  assert.ok(result);
  const sources = result.detections.map((d) => d.source);
  assert.ok(sources.includes('signature-hash'));
  assert.ok(sources.includes('heuristic'));
});
