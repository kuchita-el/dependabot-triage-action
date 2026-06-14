import type { DependabotAlert } from './github';
import type { Config, DependencyType, Vulnerability } from './types';

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
