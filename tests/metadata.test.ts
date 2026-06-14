import { describe, expect, it } from 'vitest';
import { collectM1Vulnerabilities } from '../src/metadata';
import { parseConfig } from '../src/config';
import type { Config } from '../src/types';

function cfg(overrides: Record<string, string> = {}): Config {
  return parseConfig((name) => ({ 'github-token': 'x', ...overrides })[name] ?? '');
}

/** セキュリティ更新の最小 Config（alert 情報あり）。 */
function secCfg(overrides: Record<string, string> = {}): Config {
  return cfg({
    'alert-ghsa-id': 'GHSA-aaaa-bbbb-cccc',
    'alert-cvss': '9.5',
    'dependency-names': 'left-pad, lodash',
    'package-ecosystem': 'npm',
    'dependency-type': 'direct:production',
    ...overrides,
  });
}

describe('collectM1Vulnerabilities', () => {
  it('AC1: alertGhsaId が空なら [] を返す（非セキュリティ更新）', () => {
    expect(collectM1Vulnerabilities(cfg())).toEqual([]);
    expect(collectM1Vulnerabilities(cfg({ 'dependency-names': 'left-pad' }))).toEqual([]);
  });

  it('AC2: alertGhsaId 有で単一 Vulnerability を構築する', () => {
    const vulns = collectM1Vulnerabilities(secCfg());
    expect(vulns).toHaveLength(1);
    const v = vulns[0]!;
    expect(v.ghsaId).toBe('GHSA-aaaa-bbbb-cccc');
    expect(v.packageName).toBe('left-pad'); // 先頭依存
    expect(v.ecosystem).toBe('npm');
    expect(v.cvss).toBe(9.5);
    expect(v.epss).toBe(0);
    expect(v.epssAvailable).toBe(false);
    expect(v.cveIds).toEqual([]);
  });

  it('AC3: dependencyType を scope にマップする', () => {
    expect(
      collectM1Vulnerabilities(secCfg({ 'dependency-type': 'direct:production' }))[0]!.scope,
    ).toBe('direct:production');
    expect(
      collectM1Vulnerabilities(secCfg({ 'dependency-type': 'direct:development' }))[0]!.scope,
    ).toBe('direct:development');
    expect(collectM1Vulnerabilities(secCfg({ 'dependency-type': 'indirect' }))[0]!.scope).toBe(
      'indirect',
    );
  });

  it('AC4: 未知/空の dependencyType は direct:production（最悪ケース）', () => {
    expect(collectM1Vulnerabilities(secCfg({ 'dependency-type': 'weird' }))[0]!.scope).toBe(
      'direct:production',
    );
    expect(collectM1Vulnerabilities(secCfg({ 'dependency-type': '' }))[0]!.scope).toBe(
      'direct:production',
    );
  });

  it('AC5: alertCvss が空/不正なら cvss=0', () => {
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '' }))[0]!.cvss).toBe(0);
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': 'n/a' }))[0]!.cvss).toBe(0);
  });

  it('AC6: severity を CVSS バンドから導出する', () => {
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '9.5' }))[0]!.severity).toBe('critical');
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '7.0' }))[0]!.severity).toBe('high');
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '5.0' }))[0]!.severity).toBe('moderate');
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '2.0' }))[0]!.severity).toBe('low');
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '0' }))[0]!.severity).toBe('none');
  });
});
