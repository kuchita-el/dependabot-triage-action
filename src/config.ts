import type { AggregateMethod, Config } from './types';

/**
 * input を名前で読む関数。'' は未指定を表す（GitHub Actions の getInput と同義）。
 * DI することで @actions/core をモックせず config をユニットテストできる。
 */
export type InputReader = (name: string) => string;

/** 設定不備（PAT 欠如・不正値）を表す。run() 側で setFailed に変換する。 */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * 既定値の単一ソース。action.yml の default はこれをミラーする（両者は一致させる）。
 * 値は docs/design.md に準拠。
 */
export const DEFAULTS = {
  weightCvss: 0.6,
  weightEpss: 0.4,
  scopeProd: 1.0,
  scopeDev: 0.4,
  scopeIndirect: 0.7,
  thresholdHigh: 0.66,
  thresholdMid: 0.33,
  labelHigh: 'triage:fix-now',
  labelMid: 'triage:review',
  labelLow: 'triage:low-here',
  aggregate: 'max' as AggregateMethod,
  comment: true,
  label: true,
  failOnError: false,
} as const;

/** 有限数値としてパース。未指定（空）なら既定値。不正なら ConfigError。 */
function num(read: InputReader, name: string, fallback: number): number {
  const raw = read(name).trim();
  if (raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new ConfigError(`input "${name}" は有限数値である必要があります（受領値: "${raw}"）`);
  }
  return value;
}

/** boolean としてパース。未指定なら既定値。true/false 以外は ConfigError。 */
function bool(read: InputReader, name: string, fallback: boolean): boolean {
  const raw = read(name).trim().toLowerCase();
  if (raw === '') return fallback;
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  throw new ConfigError(
    `input "${name}" は true / false である必要があります（受領値: "${read(name)}"）`,
  );
}

/**
 * 文字列を trim して読む。空白のみ（trim 後空）は未指定とみなし既定値。
 * num/bool と trim 方針を揃え、比較キー（dependency-type 等）の silent failure を防ぐ。
 */
function str(read: InputReader, name: string, fallback = ''): string {
  const raw = read(name).trim();
  return raw === '' ? fallback : raw;
}

/** カンマ区切りを配列に。各要素を trim し、空要素は除外。 */
function list(read: InputReader, name: string): string[] {
  return read(name)
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '');
}

/** aggregate をパース。未指定なら既定値。max/sum 以外は ConfigError。 */
function aggregate(read: InputReader): AggregateMethod {
  const raw = read('aggregate').trim().toLowerCase();
  if (raw === '') return DEFAULTS.aggregate;
  if (raw === 'max' || raw === 'sum') return raw;
  throw new ConfigError(
    `input "aggregate" は max / sum のいずれかである必要があります（受領値: "${raw}"）`,
  );
}

/**
 * action.yml の inputs を検証付きで Config にパースする純粋関数。
 * 設定不備は ConfigError を投げる。
 */
export function parseConfig(read: InputReader): Config {
  const githubToken = read('github-token').trim();
  if (githubToken === '') {
    throw new ConfigError(
      'input "github-token" は必須です（Dependabot alerts を読取可能な PAT を指定してください）',
    );
  }

  return {
    githubToken,

    dependencyNames: list(read, 'dependency-names'),
    dependencyType: str(read, 'dependency-type'),
    packageEcosystem: str(read, 'package-ecosystem'),
    previousVersion: str(read, 'previous-version'),
    newVersion: str(read, 'new-version'),
    dependencyGroup: str(read, 'dependency-group'),

    weightCvss: num(read, 'weight-cvss', DEFAULTS.weightCvss),
    weightEpss: num(read, 'weight-epss', DEFAULTS.weightEpss),
    scopeProd: num(read, 'scope-prod', DEFAULTS.scopeProd),
    scopeDev: num(read, 'scope-dev', DEFAULTS.scopeDev),
    scopeIndirect: num(read, 'scope-indirect', DEFAULTS.scopeIndirect),

    thresholdHigh: num(read, 'threshold-high', DEFAULTS.thresholdHigh),
    thresholdMid: num(read, 'threshold-mid', DEFAULTS.thresholdMid),
    labelHigh: str(read, 'label-high', DEFAULTS.labelHigh),
    labelMid: str(read, 'label-mid', DEFAULTS.labelMid),
    labelLow: str(read, 'label-low', DEFAULTS.labelLow),

    aggregate: aggregate(read),
    comment: bool(read, 'comment', DEFAULTS.comment),
    label: bool(read, 'label', DEFAULTS.label),
    failOnError: bool(read, 'fail-on-error', DEFAULTS.failOnError),
  };
}
