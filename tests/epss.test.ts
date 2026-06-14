import { describe, expect, it, vi } from 'vitest';
import { enrichWithEpss } from '../src/epss';
import type { EpssDeps } from '../src/epss';
import type { Vulnerability } from '../src/types';

function vuln(ghsaId: string, p: Partial<Vulnerability> = {}): Vulnerability {
  return {
    ghsaId,
    cveIds: [],
    cvss: 5,
    epss: 0,
    epssAvailable: false,
    severity: 'moderate',
    packageName: 'pkg',
    ecosystem: 'npm',
    scope: 'direct:production',
    ...p,
  };
}

describe('enrichWithEpss', () => {
  it('AC1: getCveIds の結果が vuln.cveIds に入る', async () => {
    const deps: EpssDeps = {
      getCveIds: vi.fn().mockResolvedValue(['CVE-2026-0001']),
      fetchEpss: vi.fn().mockResolvedValue({ 'CVE-2026-0001': 0.3 }),
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.cveIds).toEqual(['CVE-2026-0001']);
  });

  it('AC2: 複数 CVE の EPSS は max を採る', async () => {
    const deps: EpssDeps = {
      getCveIds: vi.fn().mockResolvedValue(['CVE-A', 'CVE-B']),
      fetchEpss: vi.fn().mockResolvedValue({ 'CVE-A': 0.3, 'CVE-B': 0.71 }),
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0.71);
  });

  it('AC3: CVE 無しは epss=0 / cveIds=[]', async () => {
    const deps: EpssDeps = {
      getCveIds: vi.fn().mockResolvedValue([]),
      fetchEpss: vi.fn().mockResolvedValue({}),
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0);
    expect(v!.cveIds).toEqual([]);
    expect(v!.epssAvailable).toBe(false);
  });

  it('AC4: 取得成功で epssAvailable=true', async () => {
    const deps: EpssDeps = {
      getCveIds: vi.fn().mockResolvedValue(['CVE-A']),
      fetchEpss: vi.fn().mockResolvedValue({ 'CVE-A': 0.5 }),
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epssAvailable).toBe(true);
  });

  it('AC5: 1件の取得失敗は当該 vuln のみフォールバックし他は正常', async () => {
    const deps: EpssDeps = {
      getCveIds: vi.fn(async (ghsa: string) => {
        if (ghsa === 'GHSA-bad') throw new Error('advisory fetch failed');
        return ['CVE-A'];
      }),
      fetchEpss: vi.fn().mockResolvedValue({ 'CVE-A': 0.5 }),
    };
    const [bad, good] = await enrichWithEpss([vuln('GHSA-bad'), vuln('GHSA-ok')], deps);
    expect(bad!.epss).toBe(0);
    expect(bad!.epssAvailable).toBe(false);
    expect(good!.epss).toBe(0.5);
    expect(good!.epssAvailable).toBe(true);
  });

  it('AC5: fetchEpss の失敗も当該 vuln のみフォールバック', async () => {
    const deps: EpssDeps = {
      getCveIds: vi.fn().mockResolvedValue(['CVE-A']),
      fetchEpss: vi.fn(async (cves: string[]) => {
        if (cves.includes('CVE-A')) throw new Error('epss api down');
        return {};
      }),
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0);
    expect(v!.epssAvailable).toBe(false);
  });

  it('AC6: 同一 GHSA が複数 vuln にまたがると getCveIds は1回だけ（メモ化）', async () => {
    const getCveIds = vi.fn().mockResolvedValue(['CVE-A']);
    const deps: EpssDeps = { getCveIds, fetchEpss: vi.fn().mockResolvedValue({ 'CVE-A': 0.5 }) };
    await enrichWithEpss([vuln('GHSA-dup'), vuln('GHSA-dup')], deps);
    expect(getCveIds).toHaveBeenCalledTimes(1);
  });

  it('入力 vulns を破壊しない（新オブジェクトを返す）', async () => {
    const deps: EpssDeps = {
      getCveIds: vi.fn().mockResolvedValue(['CVE-A']),
      fetchEpss: vi.fn().mockResolvedValue({ 'CVE-A': 0.5 }),
    };
    const input = vuln('GHSA-1');
    await enrichWithEpss([input], deps);
    expect(input.epss).toBe(0); // 元は不変
    expect(input.epssAvailable).toBe(false);
  });
});
