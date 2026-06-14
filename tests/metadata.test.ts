import { describe, expect, it } from 'vitest';
import { reconcileVulnerabilities } from '../src/metadata';
import { parseConfig } from '../src/config';
import type { DependabotAlert } from '../src/github';
import type { Config } from '../src/types';

function cfg(overrides: Record<string, string> = {}): Config {
  return parseConfig((name) => ({ 'github-token': 'x', ...overrides })[name] ?? '');
}

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

  // --- #37: 突合確度（matchConfidence） ---

  it('#37-1: new-version >= firstPatchedVersion なら version（中）', () => {
    const c = cfg({ 'dependency-names': 'left-pad', 'new-version': '1.3.0' });
    expect(reconcileVulnerabilities(c, [alert({ firstPatchedVersion: '1.3.0' })])[0]!.matchConfidence).toBe('version');
    const c2 = cfg({ 'dependency-names': 'left-pad', 'new-version': '1.4.0' });
    expect(reconcileVulnerabilities(c2, [alert({ firstPatchedVersion: '1.3.0' })])[0]!.matchConfidence).toBe('version');
  });

  it('#37-2: new-version < firstPatchedVersion なら name（緩）', () => {
    const c = cfg({ 'dependency-names': 'left-pad', 'new-version': '1.2.0' });
    expect(reconcileVulnerabilities(c, [alert({ firstPatchedVersion: '1.3.0' })])[0]!.matchConfidence).toBe('name');
  });

  it('#37-3: new-version 空（グループPR）は name（緩）', () => {
    const c = cfg({ 'dependency-names': 'left-pad' }); // new-version 未指定
    expect(reconcileVulnerabilities(c, [alert({ firstPatchedVersion: '1.3.0' })])[0]!.matchConfidence).toBe('name');
  });

  it('#37-4: firstPatchedVersion が null なら name（緩・据え置き）', () => {
    const c = cfg({ 'dependency-names': 'left-pad', 'new-version': '1.3.0' });
    expect(reconcileVulnerabilities(c, [alert({ firstPatchedVersion: null })])[0]!.matchConfidence).toBe('name');
  });

  it('#37-5: semver パース不能なら name（緩・throw しない）', () => {
    const c = cfg({ 'dependency-names': 'left-pad', 'new-version': 'not-semver' });
    expect(() =>
      reconcileVulnerabilities(c, [alert({ firstPatchedVersion: '1.3.0' })]),
    ).not.toThrow();
    expect(reconcileVulnerabilities(c, [alert({ firstPatchedVersion: '1.3.0' })])[0]!.matchConfidence).toBe('name');
    const c2 = cfg({ 'dependency-names': 'left-pad', 'new-version': '1.3.0' });
    expect(reconcileVulnerabilities(c2, [alert({ firstPatchedVersion: 'patched-soon' })])[0]!.matchConfidence).toBe('name');
  });
});
