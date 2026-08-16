// Artifact rendering.
//
// The writer still emits the shapes the old internal dashboard consumed: a
// pretty-printed report and per-package deny files. The output locations and the
// canonical serialization were never updated for the new contract.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { Finding } from './remediate.js';

function writeFile(outDir: string, relative: string, contents: string): void {
  const full = join(outDir, relative);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, contents);
}

function renderMarkdown(findings: Finding[]): string {
  const lines = ['# npm dependency remediation audit', ''];
  for (const finding of findings) {
    lines.push(`## ${finding.name}`, `- Decision: ${finding.decision}`, '');
  }
  return lines.join('\n');
}

export function writeArtifacts(outDir: string, findings: Finding[]): void {
  const overrides: Record<string, string> = {};
  for (const finding of findings) {
    if (finding.decision === 'upgrade' && finding.target_version !== null) {
      overrides[finding.name] = finding.target_version;
    }
  }

  const report = {
    generated_by: 'npmguard',
    report_version: 1,
    packages: findings,
    overrides,
    blocked: findings.filter((f) => f.decision === 'block').map((f) => f.name),
  };
  writeFile(outDir, 'report.json', JSON.stringify(report, null, 2));

  for (const finding of findings) {
    if (finding.decision === 'block') {
      writeFile(
        outDir,
        `${finding.name}.deny`,
        `Package: ${finding.name}\nInstalled: ${finding.installed_version}\nReason: ${finding.reason}\nAction: manual-review\n`,
      );
    }
  }

  writeFile(outDir, 'audit.md', renderMarkdown(findings));
}
