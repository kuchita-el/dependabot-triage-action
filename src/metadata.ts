import { gte as semverGte, valid as semverValid } from 'semver';
import type { DependabotAlert } from './github';
import type { Config, DependencyType, MatchConfidence, Vulnerability } from './types';

/** パッケージ名の正規化（小文字＋trim）。突合の照合キーに使う。 */
function normalizeName(name: string): string {
  return name.trim().toLowerCase();
}

/**
 * 突合確度を判定する（#37）。new-version が修正版（firstPatchedVersion）以上で
 * semver 比較可能なら 'version'（中）、それ以外は 'name'（緩・据え置き）。
 * グループPR（new-version 空）・firstPatchedVersion null・semver パース不能は
 * すべて 'name' にフォールバックし、throw しない。npm semver を前提とする。
 */
function classifyConfidence(newVersion: string, firstPatchedVersion: string | null): MatchConfidence {
  if (newVersion === '' || firstPatchedVersion === null) return 'name';
  if (semverValid(newVersion) === null || semverValid(firstPatchedVersion) === null) return 'name';
  return semverGte(newVersion, firstPatchedVersion) ? 'version' : 'name';
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
 * グループPR突合。PR の変更依存名（config.dependencyNames）と open alerts を
 * **パッケージ名一致のみ**で突合し、複数 Vulnerability を構築する。ecosystem は
 * 突合キーに使わない（fetch-metadata と alerts API で命名が異なり取りこぼすため）。
 * 突合自体は名前一致（緩）だが、各 Vulnerability には #37 の matchConfidence を付与し、
 * new-version が修正版以上なら 'version'（中）へ格上げする（classifyConfidence 参照）。
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
      matchConfidence: classifyConfidence(config.newVersion, a.firstPatchedVersion),
    });
  }

  return result;
}
