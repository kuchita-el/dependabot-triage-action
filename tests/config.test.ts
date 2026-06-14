import { describe, expect, it } from 'vitest';
import { parseConfig, ConfigError, DEFAULTS } from '../src/config';

/** 与えた値だけを返し、未指定キーは '' を返す InputReader を作る。 */
function reader(values: Record<string, string>): (name: string) => string {
  return (name: string) => values[name] ?? '';
}

/** github-token のみ最小限指定（他は既定値に委ねる）。 */
function minimal(extra: Record<string, string> = {}): Record<string, string> {
  return { 'github-token': 'ghp_test', ...extra };
}

describe('parseConfig', () => {
  it('AC1: 全 inputs を型付き Config にパースする', () => {
    const cfg = parseConfig(
      reader({
        'github-token': 'ghp_secret',
        'dependency-names': 'left-pad, lodash ,react',
        'dependency-type': 'direct:production',
        'package-ecosystem': 'npm',
        'previous-version': '1.0.0',
        'new-version': '1.2.3',
        'dependency-group': 'prod-deps',
        'weight-cvss': '0.7',
        'weight-epss': '0.3',
        'scope-prod': '1.0',
        'scope-dev': '0.5',
        'scope-indirect': '0.8',
        'threshold-high': '0.7',
        'threshold-mid': '0.4',
        'label-high': 'sev:high',
        'label-mid': 'sev:mid',
        'label-low': 'sev:low',
        aggregate: 'sum',
        comment: 'false',
        label: 'true',
        'fail-on-error': 'true',
      }),
    );

    expect(cfg.githubToken).toBe('ghp_secret');
    expect(cfg.dependencyNames).toEqual(['left-pad', 'lodash', 'react']);
    expect(cfg.dependencyType).toBe('direct:production');
    expect(cfg.packageEcosystem).toBe('npm');
    expect(cfg.previousVersion).toBe('1.0.0');
    expect(cfg.newVersion).toBe('1.2.3');
    expect(cfg.dependencyGroup).toBe('prod-deps');
    expect(cfg.weightCvss).toBe(0.7);
    expect(cfg.weightEpss).toBe(0.3);
    expect(cfg.scopeProd).toBe(1.0);
    expect(cfg.scopeDev).toBe(0.5);
    expect(cfg.scopeIndirect).toBe(0.8);
    expect(cfg.thresholdHigh).toBe(0.7);
    expect(cfg.thresholdMid).toBe(0.4);
    expect(cfg.labelHigh).toBe('sev:high');
    expect(cfg.labelMid).toBe('sev:mid');
    expect(cfg.labelLow).toBe('sev:low');
    expect(cfg.aggregate).toBe('sum');
    expect(cfg.comment).toBe(false);
    expect(cfg.label).toBe(true);
    expect(cfg.failOnError).toBe(true);
  });

  it('AC2: github-token が空なら ConfigError を投げる', () => {
    expect(() => parseConfig(reader({ 'github-token': '' }))).toThrow(ConfigError);
    expect(() => parseConfig(reader({}))).toThrow(ConfigError);
  });

  it('AC2: github-token の前後空白のみも空とみなす', () => {
    expect(() => parseConfig(reader({ 'github-token': '   ' }))).toThrow(ConfigError);
  });

  it('AC3: 数値 input が数値変換不能なら ConfigError を投げる', () => {
    expect(() => parseConfig(reader(minimal({ 'weight-cvss': 'abc' })))).toThrow(ConfigError);
    expect(() =>
      parseConfig(reader(minimal({ 'threshold-high': '' /* 既定で埋まる */ }))),
    ).not.toThrow();
    expect(() => parseConfig(reader(minimal({ 'scope-dev': 'NaN' })))).toThrow(ConfigError);
    expect(() => parseConfig(reader(minimal({ 'weight-epss': 'Infinity' })))).toThrow(ConfigError);
  });

  it('AC4: aggregate が max|sum 以外なら ConfigError を投げる', () => {
    expect(() => parseConfig(reader(minimal({ aggregate: 'avg' })))).toThrow(ConfigError);
  });

  it('AC4: aggregate は max / sum を受理する', () => {
    expect(parseConfig(reader(minimal({ aggregate: 'max' }))).aggregate).toBe('max');
    expect(parseConfig(reader(minimal({ aggregate: 'sum' }))).aggregate).toBe('sum');
  });

  it('AC5: 未指定の input には design.md の既定値が適用される', () => {
    const cfg = parseConfig(reader(minimal()));
    expect(cfg.weightCvss).toBe(0.6);
    expect(cfg.weightEpss).toBe(0.4);
    expect(cfg.scopeProd).toBe(1.0);
    expect(cfg.scopeDev).toBe(0.4);
    expect(cfg.scopeIndirect).toBe(0.7);
    expect(cfg.thresholdHigh).toBe(0.66);
    expect(cfg.thresholdMid).toBe(0.33);
    expect(cfg.labelHigh).toBe('triage:fix-now');
    expect(cfg.labelMid).toBe('triage:review');
    expect(cfg.labelLow).toBe('triage:low-here');
    expect(cfg.aggregate).toBe('max');
    expect(cfg.comment).toBe(true);
    expect(cfg.label).toBe(true);
    expect(cfg.failOnError).toBe(false);
    expect(cfg.dependencyNames).toEqual([]);
  });

  it('AC5: DEFAULTS が design.md の既定値と一致する', () => {
    expect(DEFAULTS.weightCvss).toBe(0.6);
    expect(DEFAULTS.weightEpss).toBe(0.4);
    expect(DEFAULTS.aggregate).toBe('max');
  });

  it('AC6: comment/label/fail-on-error の true/false 文字列を boolean にパースする', () => {
    const t = parseConfig(
      reader(minimal({ comment: 'true', label: 'false', 'fail-on-error': 'TRUE' })),
    );
    expect(t.comment).toBe(true);
    expect(t.label).toBe(false);
    expect(t.failOnError).toBe(true);
  });

  it('AC6: boolean input が true/false 以外なら ConfigError を投げる', () => {
    expect(() => parseConfig(reader(minimal({ comment: 'yes' })))).toThrow(ConfigError);
  });

  it('レビュー: パススルー文字列は trim される（dependency-type の silent failure 防止）', () => {
    const cfg = parseConfig(reader(minimal({ 'dependency-type': '  direct:production\n' })));
    expect(cfg.dependencyType).toBe('direct:production');
  });

  it('レビュー: 空白のみのパススルーは未指定（既定値）扱い', () => {
    expect(parseConfig(reader(minimal({ 'label-high': '   ' }))).labelHigh).toBe('triage:fix-now');
    expect(parseConfig(reader(minimal({ 'package-ecosystem': '  ' }))).packageEcosystem).toBe('');
  });

  it('レビュー: aggregate は大小文字非依存（bool と整合）', () => {
    expect(parseConfig(reader(minimal({ aggregate: 'MAX' }))).aggregate).toBe('max');
    expect(parseConfig(reader(minimal({ aggregate: 'Sum' }))).aggregate).toBe('sum');
  });

  // --- #36: 数値範囲・整合性バリデーション ---

  it('#36-1: 重み・スコープ係数に負値を与えると ConfigError', () => {
    for (const name of ['weight-cvss', 'weight-epss', 'scope-prod', 'scope-dev', 'scope-indirect']) {
      expect(() => parseConfig(reader(minimal({ [name]: '-0.1' })))).toThrow(ConfigError);
    }
  });

  it('#36-1: 重み・スコープ係数の 0 は受理する（境界）', () => {
    for (const name of ['weight-cvss', 'weight-epss', 'scope-prod', 'scope-dev', 'scope-indirect']) {
      expect(() => parseConfig(reader(minimal({ [name]: '0' })))).not.toThrow();
    }
  });

  it('#36-2: 閾値が 0 未満または 1 超なら ConfigError', () => {
    expect(() => parseConfig(reader(minimal({ 'threshold-high': '-0.01' })))).toThrow(ConfigError);
    expect(() => parseConfig(reader(minimal({ 'threshold-high': '1.01' })))).toThrow(ConfigError);
    expect(() => parseConfig(reader(minimal({ 'threshold-mid': '-0.01' })))).toThrow(ConfigError);
    expect(() =>
      parseConfig(reader(minimal({ 'threshold-high': '1', 'threshold-mid': '1.01' }))),
    ).toThrow(ConfigError);
  });

  it('#36-2: 閾値の境界 0 / 1 は受理する', () => {
    expect(() =>
      parseConfig(reader(minimal({ 'threshold-high': '1', 'threshold-mid': '0' }))),
    ).not.toThrow();
  });

  it('#36-3: threshold-high < threshold-mid なら ConfigError', () => {
    expect(() =>
      parseConfig(reader(minimal({ 'threshold-high': '0.3', 'threshold-mid': '0.5' }))),
    ).toThrow(ConfigError);
  });

  it('#36-3: threshold-high == threshold-mid は受理する（境界）', () => {
    expect(() =>
      parseConfig(reader(minimal({ 'threshold-high': '0.5', 'threshold-mid': '0.5' }))),
    ).not.toThrow();
  });

  it('#36-4: 範囲違反の ConfigError は input 名と受領値を含む', () => {
    expect(() => parseConfig(reader(minimal({ 'weight-cvss': '-2' })))).toThrow(/weight-cvss.*-2/);
    expect(() => parseConfig(reader(minimal({ 'threshold-high': '5' })))).toThrow(/threshold-high.*5/);
    expect(() =>
      parseConfig(reader(minimal({ 'threshold-high': '0.2', 'threshold-mid': '0.4' }))),
    ).toThrow(/threshold-high.*threshold-mid/);
  });
});
