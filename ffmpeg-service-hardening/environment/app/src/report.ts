// Artifact rendering.
//
// Writes the APT pin files, the systemd override drop-ins, the canonical JSON
// report and the Markdown audit note under the output directory.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalJson, compareCodePoints } from './canonical.js';
import { compareDeb } from './debver.js';
import type { ServiceDecision } from './policy.js';

export interface Pin {
  package: string;
  version: string;
}

function writeFile(outDir: string, relative: string, contents: string): void {
  const full = join(outDir, relative);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, contents);
}

export function pinsFor(decisions: ServiceDecision[]): Pin[] {
  const targets = new Map<string, string>();
  for (const decision of decisions) {
    if (decision.decision === 'pin' && decision.package !== null && decision.pin_version !== null) {
      const current = targets.get(decision.package);
      if (current === undefined || compareDeb(decision.pin_version, current) > 0) {
        targets.set(decision.package, decision.pin_version);
      }
    }
  }
  return [...targets.keys()]
    .sort(compareCodePoints)
    .map((name) => ({ package: name, version: targets.get(name) as string }));
}

function renderMarkdown(decisions: ServiceDecision[]): string {
  const pinned = decisions.filter((d) => d.decision === 'pin').length;
  const blocked = decisions.filter((d) => d.decision === 'block').length;
  const compliant = decisions.filter((d) => d.decision === 'ok').length;
  const lines = [
    '# FFmpeg transcode hardening audit',
    '',
    `Services scanned: ${decisions.length}`,
    `Pinned: ${pinned}`,
    `Blocked: ${blocked}`,
    `Compliant: ${compliant}`,
    '',
  ];
  for (const decision of decisions) {
    const pkg = decision.package !== null ? decision.package : 'untracked';
    const version = decision.installed_version !== null ? decision.installed_version : 'unknown';
    let verdict: string;
    if (decision.decision === 'pin') verdict = `PINNED to ${decision.pin_version}`;
    else if (decision.decision === 'block') verdict = `BLOCKED (${decision.reason})`;
    else verdict = 'COMPLIANT';
    const advisories = decision.advisories.length > 0 ? decision.advisories.join(', ') : 'none';
    lines.push(
      `## ${decision.unit}`,
      '',
      `- Executable: ${decision.exec_path}`,
      `- Package: ${pkg}`,
      `- Installed version: ${version}`,
      `- Decision: ${verdict}`,
      `- Advisories: ${advisories}`,
      '',
    );
  }
  return lines.join('\n');
}

export function writeArtifacts(outDir: string, decisions: ServiceDecision[]): void {
  const ordered = [...decisions].sort((a, b) => compareCodePoints(a.unit, b.unit));
  const pins = pinsFor(ordered);
  const blocked = ordered.filter((d) => d.decision === 'block').map((d) => d.unit).sort(compareCodePoints);

  const report = {
    generated_by: 'ffguard',
    report_version: '1',
    services: ordered,
    pins,
    blocked_units: blocked,
  };
  writeFile(outDir, 'hardening-report.json', canonicalJson(report));

  // APT pin drop-ins.
  for (const pin of pins) {
    writeFile(
      outDir,
      join('apt', 'preferences', `${pin.package}.pref`),
      `Package: ${pin.package}\nPin: version ${pin.version}\nPin-Priority: 1001\n`,
    );
  }

  // systemd override drop-ins for blocked units.
  for (const decision of ordered) {
    if (decision.decision === 'block') {
      writeFile(
        outDir,
        join('systemd', decision.unit, 'override'),
        '[Service]\nExecStart=\nExecStart=/bin/false\nNoNewPrivileges=yes\nProtectSystem=strict\n',
      );
    }
  }

  writeFile(outDir, 'ffmpeg-hardening-audit.md', renderMarkdown(ordered));
}
