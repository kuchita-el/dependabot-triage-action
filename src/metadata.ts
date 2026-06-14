import type { DependabotAlert } from './github';
import type { Config, DependencyType, Vulnerability } from './types';

/** CVSS 数値を GitHub 互換の severity バンドへ変換。 */
function severityFromCvss(cvss: number): string {
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'moderate';
  if (cvss >= 0.1) return 'low';
  return 'none';
}

/** dependency-type 文字列を DependencyType へ。未知・空は最悪ケース prod。 */
function toScope(dependencyType: string): DependencyType {
  switch (dependencyType) {
    case 'direct:development':
      return 'direct:development';
    case 'indirect':
      return 'indirect';
    case 'direct:production':
      return 'direct:production';
    default:
      return 'direct:production';
  }
}

/**
 * CVSS 文字列を数値へ。空・不正は 0。
 * score.ts の入力契約（cvss∈[0,10]）をこの層で強制し、誤設定の範囲外値を
 * [0,10] にクランプする（負値→0 / >10→10）。表示と severity の不整合・
 * 見逃し方向の沈黙を防ぐ。
 */
function parseCvss(raw: string): number {
  if (raw.trim() === '') return 0;
  const value = Number(raw);
  if (!Number.isFinite(value)) return 0;
  return Math.min(10, Math.max(0, value));
}

/**
 * M1 のメタデータ構築。fetch-metadata の出力（Config のパススルー）のみから
 * 単一の Vulnerability を組み立てる。alert 情報（ghsaId）が無ければ
 * 非セキュリティ更新として空配列を返す。
 *
 * グループ PR の alerts 突合・EPSS 実取得は後続（M2 / epss.ts）。
 */
export function collectM1Vulnerabilities(config: Config): Vulnerability[] {
  if (config.alertGhsaId === '') {
    return [];
  }

  const cvss = parseCvss(config.alertCvss);
  return [
    {
      ghsaId: config.alertGhsaId,
      cveIds: [],
      cvss,
      epss: 0,
      epssAvailable: false,
      severity: severityFromCvss(cvss),
      packageName: config.dependencyNames[0] ?? '',
      ecosystem: config.packageEcosystem,
      scope: toScope(config.dependencyType),
    },
  ];
}

/** パッケージ名の正規化（小文字＋trim）。突合の照合キーに使う。 */
function normalizeName(name: string): string {
  return name.trim().toLowerCase();
}

/** alert の dependency scope を DependencyType へ。null/未知は最悪ケース prod。 */
function alertScopeToDependencyType(scope: string | null): DependencyType {
  switch (scope) {
    case 'development':
      return 'direct:development';
    case 'runtime':
      return 'direct:production';
    default:
      return 'direct:production';
  }
}

/**
 * M2 グループPR突合（緩）。PR の変更依存名（config.dependencyNames）と
 * open alerts を**パッケージ名一致のみ**で突合し、複数 Vulnerability を構築する。
 * version 比較はしない（緩）。ecosystem は突合キーに使わない
 * （fetch-metadata と alerts API で命名が異なり取りこぼすため）。
 *
 * EPSS は付与しない（epss=0/epssAvailable=false）。実取得は呼び出し側（M2-4）で
 * enrichWithEpss に委ねる。同一 ghsaId は重複排除。突合0件は []。
 */
export function reconcileVulnerabilities(
  config: Config,
  alerts: DependabotAlert[],
): Vulnerability[] {
  const prDeps = new Set(config.dependencyNames.map(normalizeName));
  const seen = new Set<string>();
  const result: Vulnerability[] = [];

  for (const a of alerts) {
    if (!prDeps.has(normalizeName(a.packageName))) continue;
    if (seen.has(a.ghsaId)) continue;
    seen.add(a.ghsaId);
    result.push({
      ghsaId: a.ghsaId,
      cveIds: a.cveId ? [a.cveId] : [],
      cvss: a.cvss,
      epss: 0,
      epssAvailable: false,
      severity: a.severity,
      packageName: a.packageName,
      ecosystem: a.ecosystem,
      scope: alertScopeToDependencyType(a.scope),
    });
  }

  return result;
}
