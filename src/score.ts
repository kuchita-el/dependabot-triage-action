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
 * 依存スコープの係数を返す。
 * 未知のスコープ（型外の文字列が実行時に到達した場合）は fail-safe で
 * 最大係数を返す。既定では prod=1.0 が最大だが、係数はユーザ設定可能なため
 * Math.max で「設定に依らず真の最悪ケース」を保証する。
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
      return Math.max(config.scopeProd, config.scopeDev, config.scopeIndirect);
  }
}

/**
 * 脆弱性 1 件のスコア: (w_cvss · cvss/10 + w_epss · epss) · scope(depType)。
 * クランプは行わない（最終集約後に evaluate でクランプする）。
 *
 * EPSS 不明（epssAvailable=false）の場合は EPSS 項を落とし、存在する重みで
 * 再正規化する（base を presentWeight で割る）。これにより「不明」を「リスク 0」と
 * みなす下方バイアスを避け、CVSS 単独でも本来のレンジを使えるようにする。
 * presentWeight=0（w_cvss=0 かつ EPSS 不明）は 0 除算を避け base=0 とする。
 */
export function scoreVulnerability(vuln: Vulnerability, config: Config): number {
  const useEpss = vuln.epssAvailable;
  const presentWeight = config.weightCvss + (useEpss ? config.weightEpss : 0);
  const weighted =
    config.weightCvss * (vuln.cvss / 10) + (useEpss ? config.weightEpss * vuln.epss : 0);
  const base = presentWeight > 0 ? weighted / presentWeight : 0;
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
 *
 * 入力契約: 各 vuln の cvss・epss は有限数値であること（cvss∈[0,10], epss∈[0,1]）。
 * EPSS 取得失敗は上流（epss 層）で 0 にフォールバックし、cvss は metadata 層が
 * 有限値を保証する。契約違反（NaN/Infinity）は silent に low へ落とさず throw し、
 * run() 側で warning として顕在化させる（見逃し方向の沈黙を防ぐ）。
 */
export function evaluate(vulns: Vulnerability[], config: Config): ScoreResult {
  if (vulns.length === 0) {
    return { score: 0, bucket: 'none' };
  }
  for (const v of vulns) {
    if (!Number.isFinite(v.cvss) || !Number.isFinite(v.epss)) {
      throw new Error(
        `脆弱性 ${v.ghsaId} の cvss/epss が非有限です（cvss=${v.cvss}, epss=${v.epss}）。` +
          'metadata/epss 層で有限値を保証してください',
      );
    }
  }
  const scores = vulns.map((v) => scoreVulnerability(v, config));
  const score = clamp01(aggregateScores(scores, config.aggregate));
  return { score, bucket: toBucket(score, config) };
}
