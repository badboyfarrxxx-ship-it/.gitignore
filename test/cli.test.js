'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const CLI = path.join(__dirname, '..', 'bin', 'cli.js');
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

function runCli(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-scan-cli-'));
}

test('cli scan: exits 0 on a clean directory', () => {
  const dir = makeTmpDir();
  fs.writeFileSync(path.join(dir, 'clean.txt'), 'nothing bad here');

  const res = runCli(['scan', dir, '--json']);
  assert.equal(res.status, 0);
  const report = JSON.parse(res.stdout);
  assert.equal(report.threatsFound, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('cli scan: exits 1 and reports a threat without --fix', () => {
  const dir = makeTmpDir();
  fs.writeFileSync(path.join(dir, 'eicar.com'), EICAR);

  const res = runCli(['scan', dir, '--json']);
  assert.equal(res.status, 1);
  const report = JSON.parse(res.stdout);
  assert.equal(report.threatsFound, 1);
  assert.equal(fs.existsSync(path.join(dir, 'eicar.com')), true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('cli scan --fix: quarantines the threat and exits 0', () => {
  const dir = makeTmpDir();
  const quarantineDir = path.join(dir, 'qdir');
  fs.writeFileSync(path.join(dir, 'eicar.com'), EICAR);

  const res = runCli(['scan', dir, '--fix', '--quarantine-dir', quarantineDir, '--json']);
  assert.equal(res.status, 0);
  const report = JSON.parse(res.stdout);
  assert.equal(report.threatsFound, 1);
  assert.equal(report.fixedCount, 1);
  assert.equal(fs.existsSync(path.join(dir, 'eicar.com')), false);

  const list = runCli(['list-quarantine', '--quarantine-dir', quarantineDir, '--json']);
  const entries = JSON.parse(list.stdout);
  assert.equal(entries.length, 1);

  fs.chmodSync(entries[0].storedPath, 0o644);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('cli remove: refuses to delete without --force', () => {
  const dir = makeTmpDir();
  const file = path.join(dir, 'junk.txt');
  fs.writeFileSync(file, 'junk');

  const res = runCli(['remove', file]);
  assert.equal(res.status, 2);
  assert.equal(fs.existsSync(file), true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('cli help: prints usage and exits 0', () => {
  const res = runCli(['help']);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /Usage:/);
});
