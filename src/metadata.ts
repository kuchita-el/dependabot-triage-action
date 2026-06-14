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

/** CVSS 文字列を数値へ。空・不正は 0。 */
function parseCvss(raw: string): number {
  if (raw.trim() === '') return 0;
  const value = Number(raw);
  return Number.isFinite(value) ? value : 0;
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
