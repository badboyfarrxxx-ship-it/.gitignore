'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { scan } = require('../src/scanEngine');
const {
  quarantineFile,
  removeFile,
  listQuarantine,
  restoreFile,
  purgeQuarantined,
} = require('../src/quarantine');

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

function makeTmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('quarantineFile moves a detected threat out of place and records a manifest entry', () => {
  const workDir = makeTmpDir('sentinel-scan-work-');
  const quarantineDir = makeTmpDir('sentinel-scan-quarantine-');
  const targetFile = path.join(workDir, 'eicar.com');
  fs.writeFileSync(targetFile, EICAR);

  const result = scan(workDir);
  assert.equal(result.threatsFound, 1);

  const entry = quarantineFile(result.threats[0], quarantineDir);
  assert.equal(fs.existsSync(targetFile), false);
  assert.equal(fs.existsSync(entry.storedPath), true);

  const entries = listQuarantine(quarantineDir);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].id, entry.id);

  fs.rmSync(workDir, { recursive: true, force: true });
  fs.chmodSync(entry.storedPath, 0o644);
  fs.rmSync(quarantineDir, { recursive: true, force: true });
});

test('restoreFile puts a quarantined file back at its original path', () => {
  const workDir = makeTmpDir('sentinel-scan-work-');
  const quarantineDir = makeTmpDir('sentinel-scan-quarantine-');
  const targetFile = path.join(workDir, 'eicar.com');
  fs.writeFileSync(targetFile, EICAR);

  const result = scan(workDir);
  const entry = quarantineFile(result.threats[0], quarantineDir);
  assert.equal(fs.existsSync(targetFile), false);

  const restored = restoreFile(entry.id, quarantineDir);
  assert.equal(restored.restoredTo, targetFile);
  assert.equal(fs.existsSync(targetFile), true);
  assert.equal(fs.readFileSync(targetFile, 'utf8'), EICAR);
  assert.equal(listQuarantine(quarantineDir).length, 0);

  fs.rmSync(workDir, { recursive: true, force: true });
  fs.rmSync(quarantineDir, { recursive: true, force: true });
});

test('purgeQuarantined permanently deletes a quarantined item', () => {
  const workDir = makeTmpDir('sentinel-scan-work-');
  const quarantineDir = makeTmpDir('sentinel-scan-quarantine-');
  const targetFile = path.join(workDir, 'eicar.com');
  fs.writeFileSync(targetFile, EICAR);

  const result = scan(workDir);
  const entry = quarantineFile(result.threats[0], quarantineDir);

  purgeQuarantined(entry.id, quarantineDir);
  assert.equal(fs.existsSync(entry.storedPath), false);
  assert.equal(listQuarantine(quarantineDir).length, 0);

  fs.rmSync(workDir, { recursive: true, force: true });
  fs.rmSync(quarantineDir, { recursive: true, force: true });
});

test('removeFile permanently deletes a file with no quarantine step', () => {
  const workDir = makeTmpDir('sentinel-scan-work-');
  const targetFile = path.join(workDir, 'junk.txt');
  fs.writeFileSync(targetFile, 'delete me');

  removeFile(targetFile);
  assert.equal(fs.existsSync(targetFile), false);

  fs.rmSync(workDir, { recursive: true, force: true });
});

test('restoreFile throws for an unknown id', () => {
  const quarantineDir = makeTmpDir('sentinel-scan-quarantine-');
  assert.throws(() => restoreFile('does-not-exist', quarantineDir));
  fs.rmSync(quarantineDir, { recursive: true, force: true });
});
