'use strict';

const path = require('path');

const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe', '.js', '.jse',
  '.wsf', '.wsh', '.hta', '.ps1', '.psm1', '.jar', '.msi', '.dll', '.sh',
]);

const MACRO_EXTENSIONS = new Set(['.docm', '.xlsm', '.pptm', '.dotm', '.xltm']);

const NON_EXECUTABLE_CATEGORY_EXTENSIONS = new Set([
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.jpg', '.jpeg',
  '.png', '.gif', '.bmp', '.txt', '.csv', '.rtf', '.mp3', '.mp4', '.avi',
]);

/** Shannon entropy in bits/byte over the given buffer (0-8). */
function computeEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;
  const freq = new Array(256).fill(0);
  for (const byte of buffer) freq[byte] += 1;
  const len = buffer.length;
  let entropy = 0;
  for (const count of freq) {
    if (count === 0) continue;
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Sniffs a handful of well-known magic-byte signatures from a buffer. */
function detectMagicType(buffer) {
  if (!buffer || buffer.length < 4) return 'unknown';
  const b = buffer;

  if (b[0] === 0x4d && b[1] === 0x5a) return 'pe-executable'; // MZ
  if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return 'elf-executable';
  if (b[0] === 0x23 && b[1] === 0x21) return 'shell-script'; // #!
  if (b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05 || b[2] === 0x07)) return 'zip-archive';
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return 'pdf';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'jpeg';
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'png';
  if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return 'gif';
  return 'unknown';
}

const EXECUTABLE_MAGIC_TYPES = new Set(['pe-executable', 'elf-executable', 'shell-script']);

/**
 * Runs non-signature heuristic checks against a file and returns a list of
 * findings ({ id, name, severity, description }). Heuristics are inherently
 * fuzzy — they flag *suspicious*, not confirmed, indicators.
 */
function runHeuristics(filePath, buffer) {
  const findings = [];
  const ext = path.extname(filePath).toLowerCase();
  const base = path.basename(filePath).toLowerCase();

  // Double-extension masquerade, e.g. invoice.pdf.exe
  const doubleExtMatch = base.match(/\.([a-z0-9]{2,5})\.([a-z0-9]{2,5})$/);
  if (doubleExtMatch) {
    const [, first, second] = doubleExtMatch;
    if (
      NON_EXECUTABLE_CATEGORY_EXTENSIONS.has(`.${first}`) &&
      EXECUTABLE_EXTENSIONS.has(`.${second}`)
    ) {
      findings.push({
        id: 'HEUR-DOUBLE-EXTENSION',
        name: 'Double-Extension Masquerade',
        severity: 'high',
        description: `Filename disguises an executable (.${second}) behind a document/media extension (.${first}).`,
      });
    }
  }

  // Magic bytes vs. extension mismatch
  const magicType = detectMagicType(buffer);
  if (EXECUTABLE_MAGIC_TYPES.has(magicType) && NON_EXECUTABLE_CATEGORY_EXTENSIONS.has(ext)) {
    findings.push({
      id: 'HEUR-CONTENT-EXT-MISMATCH',
      name: 'Content/Extension Mismatch',
      severity: 'high',
      description: `File content looks like ${magicType} but has a "${ext}" extension — likely a disguised executable.`,
    });
  }

  // Macro-enabled Office document
  if (MACRO_EXTENSIONS.has(ext)) {
    findings.push({
      id: 'HEUR-MACRO-DOCUMENT',
      name: 'Macro-Enabled Document',
      severity: 'medium',
      description: 'Office document with macros enabled — verify the source before allowing macros to run.',
    });
  }

  // High entropy (possible packing/encryption) on a file type that isn't
  // normally compressed/encrypted itself.
  if (EXECUTABLE_EXTENSIONS.has(ext) || ext === '') {
    const entropy = computeEntropy(buffer);
    if (entropy >= 7.2 && buffer.length >= 256) {
      findings.push({
        id: 'HEUR-HIGH-ENTROPY',
        name: 'High Entropy Content',
        severity: 'low',
        description: `Entropy ${entropy.toFixed(2)} bits/byte suggests packed, encrypted, or obfuscated content.`,
      });
    }
  }

  return findings;
}

module.exports = {
  computeEntropy,
  detectMagicType,
  runHeuristics,
  EXECUTABLE_EXTENSIONS,
  MACRO_EXTENSIONS,
};
