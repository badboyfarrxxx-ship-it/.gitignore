'use strict';

const useColor = process.stdout.isTTY;
const colors = {
  red: (s) => (useColor ? `\x1b[31m${s}\x1b[0m` : s),
  yellow: (s) => (useColor ? `\x1b[33m${s}\x1b[0m` : s),
  cyan: (s) => (useColor ? `\x1b[36m${s}\x1b[0m` : s),
  green: (s) => (useColor ? `\x1b[32m${s}\x1b[0m` : s),
  bold: (s) => (useColor ? `\x1b[1m${s}\x1b[0m` : s),
  dim: (s) => (useColor ? `\x1b[2m${s}\x1b[0m` : s),
};

const severityColor = { high: colors.red, medium: colors.yellow, low: colors.cyan };

function formatTextReport(scanResult) {
  const lines = [];
  lines.push(colors.bold(`sentinel-scan report`));
  lines.push(`target:        ${scanResult.target}`);
  lines.push(`signature db:  v${scanResult.dbVersion}`);
  lines.push(`files scanned: ${scanResult.filesScanned} (skipped: ${scanResult.filesSkipped})`);
  lines.push(`duration:      ${scanResult.durationMs}ms`);
  lines.push('');

  if (scanResult.threatsFound === 0) {
    lines.push(colors.green('No threats detected.'));
    return lines.join('\n');
  }

  lines.push(colors.bold(`${scanResult.threatsFound} threat(s) found:`));
  for (const threat of scanResult.threats) {
    const colorFn = severityColor[threat.severity] || ((s) => s);
    lines.push('');
    lines.push(colorFn(`  [${threat.severity.toUpperCase()}] ${threat.filePath}`));
    lines.push(colors.dim(`    sha256: ${threat.sha256}`));
    for (const d of threat.detections) {
      lines.push(`    - (${d.source}) ${d.name}: ${d.description}`);
    }
  }
  return lines.join('\n');
}

function formatQuarantineSummary(entries) {
  if (entries.length === 0) return 'Quarantine is empty.';
  const lines = [colors.bold(`${entries.length} item(s) in quarantine:`), ''];
  for (const e of entries) {
    lines.push(`  [${e.severity.toUpperCase()}] id=${e.id}  ${e.originalPath}`);
    lines.push(colors.dim(`    quarantined: ${e.quarantinedAt}  sha256: ${e.sha256}`));
  }
  return lines.join('\n');
}

module.exports = { formatTextReport, formatQuarantineSummary };
