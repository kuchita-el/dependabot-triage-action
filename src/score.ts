import type {
  AggregateMethod,
  Bucket,
  Config,
  DependencyType,
  ScoreResult,
  Vulnerability,
} from './types';

/** 値を [0,1] に丸める。 */
function clamp01(value: number): number {
  return Math.min(1, Math.max(0, value));
}

/**
 * 依存スコープの係数を返す。未知のスコープは最悪ケース（prod）として扱う。
 */
export function scopeFactor(scope: DependencyType, config: Config): number {
  switch (scope) {
    case 'direct:development':
      return config.scopeDev;
    case 'indirect':
      return config.scopeIndirect;
    case 'direct:production':
      return config.scopeProd;
    default:
      return config.scopeProd;
  }
}

/**
 * 脆弱性 1 件のスコア: (w_cvss · cvss/10 + w_epss · epss) · scope(depType)。
 * クランプは行わない（最終集約後に evaluate でクランプする）。
 */
export function scoreVulnerability(vuln: Vulnerability, config: Config): number {
  const base = config.weightCvss * (vuln.cvss / 10) + config.weightEpss * vuln.epss;
  return base * scopeFactor(vuln.scope, config);
}

/**
 * スコア集合を集約する。max は最悪ケース駆動、sum は累積。
 * 空集合は 0（防御的。通常 evaluate が空を先に処理する）。
 */
export function aggregateScores(scores: number[], method: AggregateMethod): number {
  if (scores.length === 0) return 0;
  if (method === 'sum') {
    return scores.reduce((acc, s) => acc + s, 0);
  }
  return Math.max(...scores);
}

/**
 * スコアをバケットに変換する。閾値は以上（>=）で判定。
 * none は突合0件を表すため、ここでは返さない（evaluate が担当）。
 */
export function toBucket(score: number, config: Config): Exclude<Bucket, 'none'> {
  if (score >= config.thresholdHigh) return 'high';
  if (score >= config.thresholdMid) return 'mid';
  return 'low';
}

/**
 * PR 全体の評価。突合0件は { score: 0, bucket: 'none' }。
 * それ以外は各脆弱性スコアを集約し [0,1] にクランプしてバケット判定する。
 */
export function evaluate(vulns: Vulnerability[], config: Config): ScoreResult {
  if (vulns.length === 0) {
    return { score: 0, bucket: 'none' };
  }
  const scores = vulns.map((v) => scoreVulnerability(v, config));
  const score = clamp01(aggregateScores(scores, config.aggregate));
  return { score, bucket: toBucket(score, config) };
}
