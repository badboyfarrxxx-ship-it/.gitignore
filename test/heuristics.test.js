'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { computeEntropy, detectMagicType, runHeuristics } = require('../src/heuristics');

test('computeEntropy: empty buffer is 0', () => {
  assert.equal(computeEntropy(Buffer.alloc(0)), 0);
});

test('computeEntropy: single repeated byte is 0 (no uncertainty)', () => {
  assert.equal(computeEntropy(Buffer.alloc(1000, 0x41)), 0);
});

test('computeEntropy: uniformly random bytes approach 8 bits/byte', () => {
  const crypto = require('node:crypto');
  const entropy = computeEntropy(crypto.randomBytes(4096));
  assert.ok(entropy > 7.9, `expected near-max entropy, got ${entropy}`);
});

test('detectMagicType: recognizes PE, ELF, PDF, PNG, JPEG, zip magic bytes', () => {
  assert.equal(detectMagicType(Buffer.from([0x4d, 0x5a, 0x90, 0x00])), 'pe-executable');
  assert.equal(detectMagicType(Buffer.from([0x7f, 0x45, 0x4c, 0x46])), 'elf-executable');
  assert.equal(detectMagicType(Buffer.from('%PDF-1.4')), 'pdf');
  assert.equal(detectMagicType(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a])), 'png');
  assert.equal(detectMagicType(Buffer.from([0xff, 0xd8, 0xff, 0xe0])), 'jpeg');
  assert.equal(detectMagicType(Buffer.from([0x50, 0x4b, 0x03, 0x04])), 'zip-archive');
  assert.equal(detectMagicType(Buffer.from('plain text')), 'unknown');
});

test('runHeuristics: flags a double-extension executable masquerade', () => {
  const findings = runHeuristics('invoice.pdf.exe', Buffer.from('MZ fake payload'));
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes('HEUR-DOUBLE-EXTENSION'));
});

test('runHeuristics: flags content/extension mismatch (PE bytes, .txt extension)', () => {
  const peLike = Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(100, 0x90)]);
  const findings = runHeuristics('notes.txt', peLike);
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes('HEUR-CONTENT-EXT-MISMATCH'));
});

test('runHeuristics: flags macro-enabled office documents', () => {
  const findings = runHeuristics('budget.xlsm', Buffer.from('PK\x03\x04'));
  assert.ok(findings.some((f) => f.id === 'HEUR-MACRO-DOCUMENT'));
});

test('runHeuristics: does not flag a normal small text file', () => {
  const findings = runHeuristics('readme.txt', Buffer.from('hello world, nothing suspicious here'));
  assert.deepEqual(findings, []);
});
