#!/usr/bin/env node
'use strict';

const fs = require('fs');
const crypto = require('crypto');

const { scan, scanBuffer } = require('../src/scanEngine');
const { loadSignatureDb, updateSignatureDb, DEFAULT_DB_PATH } = require('../src/signatureDb');
const {
  DEFAULT_QUARANTINE_DIR,
  quarantineFile,
  removeFile,
  listQuarantine,
  restoreFile,
  purgeQuarantined,
} = require('../src/quarantine');
const { formatTextReport, formatQuarantineSummary } = require('../src/report');
const { readFileCapped } = require('../src/fileUtils');
const { DEFAULT_MAX_FILE_BYTES } = require('../src/scanEngine');

const EXIT_CLEAN = 0;
const EXIT_THREATS_FOUND = 1;
const EXIT_ERROR = 2;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        if (key === 'exclude') {
          args.exclude = args.exclude || [];
          args.exclude.push(next);
        } else {
          args[key] = next;
        }
        i += 1;
      } else {
        args[key] = true;
      }
    } else {
      args._.push(arg);
    }
  }
  return args;
}

function printHelp() {
  console.log(`sentinel-scan — signature + heuristic malware scanner

Usage:
  sentinel-scan scan <path> [options]        Scan a file or directory
  sentinel-scan quarantine <file>             Quarantine a specific file
  sentinel-scan remove <file> --force         Permanently delete a file (no quarantine)
  sentinel-scan restore <id>                  Restore a quarantined file to its original path
  sentinel-scan purge <id>                    Permanently delete a quarantined item
  sentinel-scan list-quarantine               List quarantined items
  sentinel-scan update-db <feed.json>         Merge a signature feed into the database

Scan options:
  --db <path>              Signature database file (default: bundled data/signatures.json)
  --json                   Output machine-readable JSON instead of text
  --fix                    Automatically quarantine every threat found
  --quarantine-dir <dir>   Quarantine directory (default: ./.quarantine)
  --max-file-mb <n>        Skip files larger than n MB (default: 50)
  --exclude <name>         Directory name to skip (repeatable; default: .git, node_modules, .quarantine)

Exit codes: 0 = clean/all threats fixed, 1 = threats found, 2 = error.
`);
}

function cmdScan(args) {
  const target = args._[1];
  if (!target) {
    console.error('Error: scan requires a <path> argument.');
    return EXIT_ERROR;
  }
  if (!fs.existsSync(target)) {
    console.error(`Error: path not found: ${target}`);
    return EXIT_ERROR;
  }

  const quarantineDir = args['quarantine-dir'] || DEFAULT_QUARANTINE_DIR;
  const maxFileBytes = args['max-file-mb'] ? Number(args['max-file-mb']) * 1024 * 1024 : DEFAULT_MAX_FILE_BYTES;

  const result = scan(target, {
    dbPath: args.db || DEFAULT_DB_PATH,
    maxFileBytes,
    excludes: args.exclude ? new Set(['.git', 'node_modules', '.quarantine', ...args.exclude]) : undefined,
  });

  let fixedCount = 0;
  if (args.fix) {
    for (const threat of result.threats) {
      try {
        quarantineFile(threat, quarantineDir);
        fixedCount += 1;
      } catch (err) {
        console.error(`Failed to quarantine ${threat.filePath}: ${err.message}`);
      }
    }
  }

  if (args.json) {
    console.log(JSON.stringify({ ...result, fixedCount }, null, 2));
  } else {
    console.log(formatTextReport(result));
    if (args.fix) {
      console.log(`\n${fixedCount}/${result.threatsFound} threat(s) quarantined to ${quarantineDir}`);
    }
  }

  if (result.threatsFound === 0) return EXIT_CLEAN;
  if (args.fix && fixedCount === result.threatsFound) return EXIT_CLEAN;
  return EXIT_THREATS_FOUND;
}

function cmdQuarantine(args) {
  const target = args._[1];
  if (!target) {
    console.error('Error: quarantine requires a <file> argument.');
    return EXIT_ERROR;
  }
  if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
    console.error(`Error: not a file: ${target}`);
    return EXIT_ERROR;
  }

  const db = loadSignatureDb(args.db || DEFAULT_DB_PATH);
  const { buffer, truncated } = readFileCapped(target, DEFAULT_MAX_FILE_BYTES);
  if (truncated) {
    console.error('Error: file too large to scan; refusing to quarantine without scan metadata.');
    return EXIT_ERROR;
  }

  let scanResult = scanBuffer(target, buffer, db);
  if (!scanResult) {
    if (!args.force) {
      console.log('No threat signatures matched this file. Use --force to quarantine it anyway.');
      return EXIT_CLEAN;
    }
    scanResult = {
      filePath: target,
      sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
      size: buffer.length,
      severity: 'low',
      detections: [{ id: 'MANUAL', name: 'Manual Quarantine', severity: 'low', description: 'Quarantined manually by user request.', source: 'manual' }],
    };
  }

  const quarantineDir = args['quarantine-dir'] || DEFAULT_QUARANTINE_DIR;
  const entry = quarantineFile(scanResult, quarantineDir);
  console.log(`Quarantined: ${entry.originalPath} -> ${entry.storedPath} (id=${entry.id})`);
  return EXIT_CLEAN;
}

function cmdRemove(args) {
  const target = args._[1];
  if (!target) {
    console.error('Error: remove requires a <file> argument.');
    return EXIT_ERROR;
  }
  if (!args.force) {
    console.error('Refusing to permanently delete without --force. Use "quarantine" for a reversible action.');
    return EXIT_ERROR;
  }
  removeFile(target);
  console.log(`Permanently removed: ${target}`);
  return EXIT_CLEAN;
}

function cmdRestore(args) {
  const id = args._[1];
  if (!id) {
    console.error('Error: restore requires an <id> argument.');
    return EXIT_ERROR;
  }
  const quarantineDir = args['quarantine-dir'] || DEFAULT_QUARANTINE_DIR;
  const entry = restoreFile(id, quarantineDir);
  console.log(`Restored: ${entry.storedPath} -> ${entry.restoredTo}`);
  return EXIT_CLEAN;
}

function cmdPurge(args) {
  const id = args._[1];
  if (!id) {
    console.error('Error: purge requires an <id> argument.');
    return EXIT_ERROR;
  }
  const quarantineDir = args['quarantine-dir'] || DEFAULT_QUARANTINE_DIR;
  const entry = purgeQuarantined(id, quarantineDir);
  console.log(`Purged: ${entry.originalPath} (id=${entry.id})`);
  return EXIT_CLEAN;
}

function cmdListQuarantine(args) {
  const quarantineDir = args['quarantine-dir'] || DEFAULT_QUARANTINE_DIR;
  const entries = listQuarantine(quarantineDir);
  if (args.json) {
    console.log(JSON.stringify(entries, null, 2));
  } else {
    console.log(formatQuarantineSummary(entries));
  }
  return EXIT_CLEAN;
}

function cmdUpdateDb(args) {
  const feed = args._[1];
  if (!feed) {
    console.error('Error: update-db requires a <feed.json> argument.');
    return EXIT_ERROR;
  }
  const dbPath = args.db || DEFAULT_DB_PATH;
  const result = updateSignatureDb(dbPath, feed);
  console.log(
    `Signature DB updated: +${result.addedHashes} hash signature(s), +${result.addedPatterns} pattern signature(s). ` +
      `Totals: ${result.totalHashes} hashes, ${result.totalPatterns} patterns.`
  );
  return EXIT_CLEAN;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];

  if (!command || command === 'help' || args.help) {
    printHelp();
    return EXIT_CLEAN;
  }

  const handlers = {
    scan: cmdScan,
    quarantine: cmdQuarantine,
    remove: cmdRemove,
    restore: cmdRestore,
    purge: cmdPurge,
    'list-quarantine': cmdListQuarantine,
    'update-db': cmdUpdateDb,
  };

  const handler = handlers[command];
  if (!handler) {
    console.error(`Unknown command: ${command}\n`);
    printHelp();
    return EXIT_ERROR;
  }

  try {
    return handler(args);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    return EXIT_ERROR;
  }
}

process.exitCode = main();
