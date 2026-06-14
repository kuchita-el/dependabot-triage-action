import { describe, expect, it } from 'vitest';
import { collectM1Vulnerabilities, reconcileVulnerabilities } from '../src/metadata';
import { parseConfig } from '../src/config';
import type { DependabotAlert } from '../src/github';
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

  it('レビュー: cvss は契約 [0,10] にクランプする（誤設定の silent miss/不正表示を防ぐ）', () => {
    // 過大値（例: 9.5 を 95 と誤入力）→ 10、severity も critical で整合
    const over = collectM1Vulnerabilities(secCfg({ 'alert-cvss': '95' }))[0]!;
    expect(over.cvss).toBe(10);
    expect(over.severity).toBe('critical');
    // 負値 → 0、severity none
    const neg = collectM1Vulnerabilities(secCfg({ 'alert-cvss': '-1' }))[0]!;
    expect(neg.cvss).toBe(0);
    expect(neg.severity).toBe('none');
  });

  it('AC6: severity を CVSS バンドから導出する', () => {
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '9.5' }))[0]!.severity).toBe('critical');
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '7.0' }))[0]!.severity).toBe('high');
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '5.0' }))[0]!.severity).toBe('moderate');
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '2.0' }))[0]!.severity).toBe('low');
    expect(collectM1Vulnerabilities(secCfg({ 'alert-cvss': '0' }))[0]!.severity).toBe('none');
  });
});

function alert(p: Partial<DependabotAlert> = {}): DependabotAlert {
  return {
    ghsaId: 'GHSA-aaaa-bbbb-cccc',
    cveId: 'CVE-2026-0001',
    severity: 'high',
    cvss: 7.5,
    ecosystem: 'npm',
    packageName: 'left-pad',
    scope: 'runtime',
    firstPatchedVersion: '1.3.0',
    vulnerableVersionRange: '< 1.3.0',
    ...p,
  };
}

describe('reconcileVulnerabilities', () => {
  it('AC1: dependency-names に名前一致する alert は Vulnerability になる', () => {
    const vulns = reconcileVulnerabilities(cfg({ 'dependency-names': 'left-pad' }), [alert()]);
    expect(vulns).toHaveLength(1);
    expect(vulns[0]!.packageName).toBe('left-pad');
  });

  it('AC2: 名前一致しない alert は除外される', () => {
    const vulns = reconcileVulnerabilities(cfg({ 'dependency-names': 'lodash' }), [
      alert({ packageName: 'left-pad' }),
    ]);
    expect(vulns).toEqual([]);
  });

  it('AC3: 名前正規化(大文字小文字/前後空白)を跨いでマッチ', () => {
    // dependency-names: 'Left-Pad'（config は trim のみ・大小は保持）、alert: ' left-pad '
    const vulns = reconcileVulnerabilities(cfg({ 'dependency-names': 'Left-Pad' }), [
      alert({ packageName: ' left-pad ' }),
    ]);
    expect(vulns).toHaveLength(1);
  });

  it('AC4: 複数マッチで複数 Vulnerability', () => {
    const vulns = reconcileVulnerabilities(cfg({ 'dependency-names': 'left-pad, lodash' }), [
      alert({ ghsaId: 'GHSA-1', packageName: 'left-pad' }),
      alert({ ghsaId: 'GHSA-2', packageName: 'lodash' }),
    ]);
    expect(vulns).toHaveLength(2);
  });

  it('AC5: 同一 ghsaId は重複排除', () => {
    const vulns = reconcileVulnerabilities(cfg({ 'dependency-names': 'left-pad' }), [
      alert({ ghsaId: 'GHSA-dup', packageName: 'left-pad' }),
      alert({ ghsaId: 'GHSA-dup', packageName: 'left-pad' }),
    ]);
    expect(vulns).toHaveLength(1);
  });

  it('AC6: 突合0件は []', () => {
    expect(reconcileVulnerabilities(cfg({ 'dependency-names': 'left-pad' }), [])).toEqual([]);
    expect(reconcileVulnerabilities(cfg(), [alert()])).toEqual([]); // dependency-names 空
  });

  it('AC7: 各フィールドを alert から正しくマップする', () => {
    const [v] = reconcileVulnerabilities(cfg({ 'dependency-names': 'left-pad' }), [
      alert({
        ghsaId: 'GHSA-x',
        cveId: 'CVE-2026-9999',
        severity: 'critical',
        cvss: 9.8,
        ecosystem: 'npm',
        packageName: 'left-pad',
      }),
    ]);
    expect(v).toMatchObject({
      ghsaId: 'GHSA-x',
      cveIds: ['CVE-2026-9999'],
      cvss: 9.8,
      epss: 0,
      epssAvailable: false,
      severity: 'critical',
      packageName: 'left-pad',
      ecosystem: 'npm',
    });
  });

  it('AC7: cveId が null なら cveIds=[]', () => {
    const [v] = reconcileVulnerabilities(cfg({ 'dependency-names': 'left-pad' }), [
      alert({ cveId: null }),
    ]);
    expect(v!.cveIds).toEqual([]);
  });

  it('AC8: alert.scope を DependencyType にマップ', () => {
    const c = cfg({ 'dependency-names': 'left-pad' });
    expect(reconcileVulnerabilities(c, [alert({ scope: 'runtime' })])[0]!.scope).toBe(
      'direct:production',
    );
    expect(reconcileVulnerabilities(c, [alert({ scope: 'development' })])[0]!.scope).toBe(
      'direct:development',
    );
    expect(reconcileVulnerabilities(c, [alert({ scope: null })])[0]!.scope).toBe(
      'direct:production',
    );
  });
});
