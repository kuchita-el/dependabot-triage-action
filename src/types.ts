/**
 * ドメイン全体で共有する型。
 * 設計合意は docs/design.md を参照。
 */

/** 依存のスコープ（fetch-metadata の dependency-type に対応）。 */
export type DependencyType = 'direct:production' | 'direct:development' | 'indirect';

/** PR 全体スコアのバケット。none は突合0件（非セキュリティ更新）。 */
export type Bucket = 'high' | 'mid' | 'low' | 'none';

/** PR 全体スコアの集約方式。 */
export type AggregateMethod = 'max' | 'sum';

/**
 * 突合確度。
 * - 'name': パッケージ名一致のみ（緩）。このPRが解決するかは未検証。
 * - 'version': new-version が修正版（firstPatchedVersion）以上で解決見込み（中）。
 */
export type MatchConfidence = 'name' | 'version';

/** 1 件の脆弱性（alert / advisory から組み立てる）。 */
export interface Vulnerability {
  /** GHSA ID（例: GHSA-xxxx-xxxx-xxxx）。 */
  ghsaId: string;
  /** GHSA に紐づく CVE ID 群（0 件以上）。 */
  cveIds: string[];
  /** CVSS スコア（0..10）。v3/v4 の max。 */
  cvss: number;
  /** EPSS（0..1）。取得失敗時・未取得時は 0（score 用のフォールバック値）。 */
  epss: number;
  /**
   * EPSS が実際に取得できたか。false は未取得（M1 は EPSS を取得しないため常に false）。
   * score は epss(数値) を使うが、コメント表示は本フラグで「—（未取得）」と数値を出し分ける。
   */
  epssAvailable: boolean;
  /** GitHub severity（low | moderate | high | critical）。 */
  severity: string;
  /** パッケージ名。 */
  packageName: string;
  /** package-ecosystem（npm, pip, ...）。 */
  ecosystem: string;
  /** この脆弱性のスコープ（スコープ係数の決定に使う）。 */
  scope: DependencyType;
  /**
   * 突合確度（#37）。name=名前一致のみ（緩）、version=バージョン検証済（中）。
   * コメント表示の確度マーク・バナー文言の出し分けに使う。score には影響しない。
   */
  matchConfidence: MatchConfidence;
}

/** PR 全体のスコア評価結果。 */
export interface ScoreResult {
  /** PR 全体スコア（[0,1] にクランプ済み）。 */
  score: number;
  /** スコア（と突合有無）から決まるバケット。 */
  bucket: Bucket;
}

/** action.yml の inputs をパース・検証した結果。 */
export interface Config {
  // --- 認証 ---
  githubToken: string;

  // --- fetch-metadata パススルー ---
  dependencyNames: string[];
  dependencyType: string;
  packageEcosystem: string;
  previousVersion: string;
  newVersion: string;
  dependencyGroup: string;

  // --- スコア重み・スコープ係数 ---
  weightCvss: number;
  weightEpss: number;
  scopeProd: number;
  scopeDev: number;
  scopeIndirect: number;

  // --- バケット閾値 / ラベル名 ---
  thresholdHigh: number;
  thresholdMid: number;
  labelHigh: string;
  labelMid: string;
  labelLow: string;

  // --- 集約・挙動トグル ---
  aggregate: AggregateMethod;
  comment: boolean;
  label: boolean;
  failOnError: boolean;
}
