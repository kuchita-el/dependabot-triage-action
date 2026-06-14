import { describe, expect, it } from 'vitest';
import { scopeFactor, scoreVulnerability, aggregateScores, toBucket, evaluate } from '../src/score';
import { parseConfig } from '../src/config';
import type { Config, DependencyType, Vulnerability } from '../src/types';

/** 既定値 Config を作り、必要なら一部を上書きした reader でパースする。 */
function cfg(overrides: Record<string, string> = {}): Config {
  return parseConfig((name) => ({ 'github-token': 'x', ...overrides })[name] ?? '');
}

/** Vulnerability ファクトリ。 */
function vuln(p: Partial<Vulnerability> = {}): Vulnerability {
  return {
    ghsaId: 'GHSA-aaaa-bbbb-cccc',
    cveIds: [],
    cvss: 9.0,
    epss: 0.5,
    epssAvailable: true,
    severity: 'high',
    packageName: 'pkg',
    ecosystem: 'npm',
    scope: 'direct:production',
    matchConfidence: 'name',
    ...p,
  };
}

describe('scopeFactor', () => {
  it('AC1: depType ごとに config の係数を返す', () => {
    const c = cfg();
    expect(scopeFactor('direct:production', c)).toBe(1.0);
    expect(scopeFactor('direct:development', c)).toBe(0.4);
    expect(scopeFactor('indirect', c)).toBe(0.7);
  });

  it('AC1: カスタム係数を反映する', () => {
    const c = cfg({ 'scope-prod': '0.9', 'scope-dev': '0.2', 'scope-indirect': '0.55' });
    expect(scopeFactor('direct:production', c)).toBe(0.9);
    expect(scopeFactor('direct:development', c)).toBe(0.2);
    expect(scopeFactor('indirect', c)).toBe(0.55);
  });

  it('レビュー: 未知スコープは最大係数（config 依存でも真の最悪ケース）', () => {
    // scope-indirect を prod より大きくしても、未知は最大(2.0)を返す
    const c = cfg({ 'scope-prod': '1.0', 'scope-dev': '0.4', 'scope-indirect': '2.0' });
    expect(scopeFactor('unknown-scope' as unknown as DependencyType, c)).toBe(2.0);
  });
});

describe('scoreVulnerability', () => {
  it('AC2: (w_cvss·cvss/10 + w_epss·epss)·scope を計算する', () => {
    // (0.6*9.0/10 + 0.4*0.5)*1.0 = 0.54 + 0.2 = 0.74
    expect(scoreVulnerability(vuln({ cvss: 9.0, epss: 0.5 }), cfg())).toBeCloseTo(0.74, 10);
  });

  it('AC2: スコープ係数が乗じられる（dev=0.4）', () => {
    // 0.74 * 0.4 = 0.296
    const v = vuln({ cvss: 9.0, epss: 0.5, scope: 'direct:development' });
    expect(scoreVulnerability(v, cfg())).toBeCloseTo(0.296, 10);
  });

  it('AC2: カスタム重みを反映する', () => {
    // (0.5*8.0/10 + 0.5*0.2)*1.0 = 0.4 + 0.1 = 0.5
    const v = vuln({ cvss: 8.0, epss: 0.2 });
    expect(scoreVulnerability(v, cfg({ 'weight-cvss': '0.5', 'weight-epss': '0.5' }))).toBeCloseTo(
      0.5,
      10,
    );
  });
});

describe('aggregateScores', () => {
  it('AC3: max は最大値を返す', () => {
    expect(aggregateScores([0.2, 0.74, 0.5], 'max')).toBeCloseTo(0.74, 10);
  });

  it('AC3: sum は合計を返す', () => {
    expect(aggregateScores([0.2, 0.3, 0.1], 'sum')).toBeCloseTo(0.6, 10);
  });

  it('空配列は 0 を返す（防御的）', () => {
    expect(aggregateScores([], 'max')).toBe(0);
    expect(aggregateScores([], 'sum')).toBe(0);
  });
});

describe('toBucket', () => {
  it('AC4: 閾値境界で high/mid/low を分ける', () => {
    const c = cfg(); // threshold-high=0.66, threshold-mid=0.33
    expect(toBucket(0.66, c)).toBe('high'); // 境界ちょうど → high
    expect(toBucket(0.65, c)).toBe('mid');
    expect(toBucket(0.33, c)).toBe('mid'); // 境界ちょうど → mid
    expect(toBucket(0.32, c)).toBe('low');
    expect(toBucket(0.0, c)).toBe('low');
  });

  it('AC4: カスタム閾値を反映する', () => {
    const c = cfg({ 'threshold-high': '0.8', 'threshold-mid': '0.5' });
    expect(toBucket(0.8, c)).toBe('high');
    expect(toBucket(0.79, c)).toBe('mid');
    expect(toBucket(0.5, c)).toBe('mid');
    expect(toBucket(0.49, c)).toBe('low');
  });
});

describe('evaluate', () => {
  it('AC5: 空 vulns は { score: 0, bucket: none }', () => {
    expect(evaluate([], cfg())).toEqual({ score: 0, bucket: 'none' });
  });

  it('単一脆弱性: max 集約でスコアとバケットを返す', () => {
    const r = evaluate([vuln({ cvss: 9.0, epss: 0.5 })], cfg());
    expect(r.score).toBeCloseTo(0.74, 10);
    expect(r.bucket).toBe('high');
  });

  it('複数脆弱性: max は最悪ケース駆動', () => {
    const vulns = [vuln({ cvss: 2.0, epss: 0.1 }), vuln({ cvss: 9.0, epss: 0.5 })];
    const r = evaluate(vulns, cfg());
    expect(r.score).toBeCloseTo(0.74, 10);
    expect(r.bucket).toBe('high');
  });

  it('AC6: 最終スコアは [0,1] にクランプされる（sum で 1 超過）', () => {
    const vulns = [vuln({ cvss: 9.0, epss: 0.5 }), vuln({ cvss: 9.0, epss: 0.5 })];
    // sum = 0.74 + 0.74 = 1.48 → clamp 1.0
    const r = evaluate(vulns, cfg({ aggregate: 'sum' }));
    expect(r.score).toBe(1.0);
    expect(r.bucket).toBe('high');
  });

  it('AC6: 負の重みでもスコアは 0 未満にならない', () => {
    // #36 で parseConfig は負の重みを弾くため、評価器の防御的下限（クランプ）は
    // Config を直接構築して検証する（score.ts は parseConfig 以外からも呼ばれうる純粋関数）。
    const c: Config = { ...cfg(), weightCvss: -1 };
    const r = evaluate([vuln({ cvss: 1.0, epss: 0.0 })], c);
    expect(r.score).toBeGreaterThanOrEqual(0);
  });

  it('レビュー: cvss/epss が非有限なら throw する（NaN の silent-miss 防止）', () => {
    expect(() => evaluate([vuln({ cvss: NaN })], cfg())).toThrow(/cvss|epss/);
    expect(() => evaluate([vuln({ epss: Number.POSITIVE_INFINITY })], cfg())).toThrow(/cvss|epss/);
    // 1 件でも非有限があれば全体を throw（silent に low へ落とさない）
    expect(() => evaluate([vuln({ cvss: 9.0, epss: 0.5 }), vuln({ cvss: NaN })], cfg())).toThrow();
  });
});
