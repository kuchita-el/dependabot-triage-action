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
    matchConfidence: 'name',
    ...p,
  };
}

describe('enrichWithEpss', () => {
  it('AC1: getAdvisory の cveIds が vuln.cveIds に入る', async () => {
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-2026-0001'], githubEpss: null }),
      fetchEpss: vi.fn().mockResolvedValue({ 'CVE-2026-0001': 0.3 }),
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.cveIds).toEqual(['CVE-2026-0001']);
  });

  it('A案: GitHub epss(percentage) があればそれを採用し FIRST を呼ばない', async () => {
    const fetchEpss = vi.fn().mockResolvedValue({ 'CVE-A': 0.99 });
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-A'], githubEpss: 0.42 }),
      fetchEpss,
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0.42);
    expect(v!.epssAvailable).toBe(true);
    expect(v!.cveIds).toEqual(['CVE-A']); // CVE は表示用に保持
    expect(fetchEpss).not.toHaveBeenCalled(); // FIRST へは流れない
  });

  it('A案: GitHub epss=0（有限の0）も採用する（null と区別、FIRST へ流れない）', async () => {
    const fetchEpss = vi.fn().mockResolvedValue({ 'CVE-A': 0.5 });
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-A'], githubEpss: 0 }),
      fetchEpss,
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0);
    expect(v!.epssAvailable).toBe(true);
    expect(fetchEpss).not.toHaveBeenCalled();
  });

  it('A案: GitHub epss が null なら FIRST へフォールバックし複数 CVE の max を採る', async () => {
    const fetchEpss = vi.fn().mockResolvedValue({ 'CVE-A': 0.3, 'CVE-B': 0.71 });
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-A', 'CVE-B'], githubEpss: null }),
      fetchEpss,
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0.71);
    expect(v!.epssAvailable).toBe(true);
    expect(fetchEpss).toHaveBeenCalledTimes(1);
  });

  it('A案: CVE 未割当でも GitHub epss が有限なら採用（cveIds=[] かつ epssAvailable=true）', async () => {
    const fetchEpss = vi.fn().mockResolvedValue({});
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: [], githubEpss: 0.12 }),
      fetchEpss,
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0.12);
    expect(v!.epssAvailable).toBe(true);
    expect(v!.cveIds).toEqual([]); // CVE 欄は「—」、EPSS 欄は数値で独立表示
    expect(fetchEpss).not.toHaveBeenCalled();
  });

  it('AC4: CVE 未割当（githubEpss=null かつ cveIds=[]）は epss=0 / epssAvailable=false', async () => {
    const fetchEpss = vi.fn().mockResolvedValue({});
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: [], githubEpss: null }),
      fetchEpss,
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0);
    expect(v!.cveIds).toEqual([]);
    expect(v!.epssAvailable).toBe(false);
    expect(fetchEpss).not.toHaveBeenCalled(); // CVE 0 件で FIRST は呼ばない
  });

  it('AC5: getAdvisory の失敗は当該 vuln のみフォールバックし他は正常', async () => {
    const deps: EpssDeps = {
      getAdvisory: vi.fn(async (ghsa: string) => {
        if (ghsa === 'GHSA-bad') throw new Error('advisory fetch failed');
        return { cveIds: ['CVE-A'], githubEpss: 0.5 };
      }),
      fetchEpss: vi.fn().mockResolvedValue({ 'CVE-A': 0.5 }),
    };
    const [bad, good] = await enrichWithEpss([vuln('GHSA-bad'), vuln('GHSA-ok')], deps);
    expect(bad!.epss).toBe(0);
    expect(bad!.epssAvailable).toBe(false);
    expect(good!.epss).toBe(0.5);
    expect(good!.epssAvailable).toBe(true);
  });

  it('AC5: fetchEpss の失敗（FIRST フォールバック経路）も当該 vuln のみフォールバック', async () => {
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-A'], githubEpss: null }),
      fetchEpss: vi.fn(async (cves: string[]) => {
        if (cves.includes('CVE-A')) throw new Error('epss api down');
        return {};
      }),
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0);
    expect(v!.epssAvailable).toBe(false);
  });

  it('レビュー: CVE はあるが GitHub epss=null かつ FIRST 未収載なら epssAvailable=false（取得済み0と区別）', async () => {
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-UNSCORED'], githubEpss: null }),
      fetchEpss: vi.fn().mockResolvedValue({}), // EPSS 応答に当該 CVE が現れない
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0);
    expect(v!.epssAvailable).toBe(false);
    expect(v!.cveIds).toEqual(['CVE-UNSCORED']); // CVE 自体は保持
  });

  it('レビュー: FIRST フォールバックで非有限値(NaN)を返しても throw せず epssAvailable=false に倒す', async () => {
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-BAD'], githubEpss: null }),
      fetchEpss: vi.fn().mockResolvedValue({ 'CVE-BAD': NaN }), // 異常応答
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0);
    expect(v!.epssAvailable).toBe(false);
    expect(Number.isFinite(v!.epss)).toBe(true); // 非有限を伝播させない
  });

  it('レビュー: GitHub epss が非有限値(NaN)なら採用せず FIRST へフォールバック', async () => {
    const fetchEpss = vi.fn().mockResolvedValue({ 'CVE-A': 0.6 });
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-A'], githubEpss: NaN }),
      fetchEpss,
    };
    const [v] = await enrichWithEpss([vuln('GHSA-1')], deps);
    expect(v!.epss).toBe(0.6);
    expect(v!.epssAvailable).toBe(true);
    expect(fetchEpss).toHaveBeenCalledTimes(1);
  });

  it('AC6: 同一 GHSA が複数 vuln にまたがると getAdvisory は1回だけ（メモ化）', async () => {
    const getAdvisory = vi.fn().mockResolvedValue({ cveIds: ['CVE-A'], githubEpss: 0.5 });
    const deps: EpssDeps = { getAdvisory, fetchEpss: vi.fn().mockResolvedValue({ 'CVE-A': 0.5 }) };
    await enrichWithEpss([vuln('GHSA-dup'), vuln('GHSA-dup')], deps);
    expect(getAdvisory).toHaveBeenCalledTimes(1);
  });

  it('入力 vulns を破壊しない（新オブジェクトを返す）', async () => {
    const deps: EpssDeps = {
      getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-A'], githubEpss: 0.5 }),
      fetchEpss: vi.fn().mockResolvedValue({ 'CVE-A': 0.5 }),
    };
    const input = vuln('GHSA-1');
    await enrichWithEpss([input], deps);
    expect(input.epss).toBe(0); // 元は不変
    expect(input.epssAvailable).toBe(false);
  });
});
