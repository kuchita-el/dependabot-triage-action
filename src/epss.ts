import type { Vulnerability } from './types';

/**
 * EPSS 取得の外部依存。実 octokit/HTTP は main.ts（合成ルート）が注入する。
 * - getCveIds: GHSA ID → 紐づく CVE 群（securityAdvisories.getGlobalAdvisory 相当）
 * - fetchEpss: CVE 群 → CVE ごとの EPSS スコア（FIRST EPSS API 相当）
 */
export interface EpssDeps {
  getCveIds: (ghsaId: string) => Promise<string[]>;
  fetchEpss: (cveIds: string[]) => Promise<Record<string, number>>;
}

/**
 * 脆弱性集合に EPSS を付与する。各 vuln の GHSA→CVE→EPSS を解決し、
 * epss は複数 CVE の max（最悪ケース駆動）。取得失敗時は当該 vuln のみ
 * epss=0 / epssAvailable=false にフォールバックし、他 vuln の処理は止めない。
 *
 * GHSA→CVE はメモ化（同一 GHSA の重複取得を避ける）。fetchEpss は per-vuln の
 * 失敗分離を優先して跨 vuln メモ化しない（vuln は GHSA で一意のため実益も小さい）。
 * 入力 vulns は破壊せず新オブジェクトを返す。
 */
export async function enrichWithEpss(
  vulns: Vulnerability[],
  deps: EpssDeps,
): Promise<Vulnerability[]> {
  // GHSA→CVE の Promise メモ化（並列でも 1 GHSA 1 回）。
  const cveCache = new Map<string, Promise<string[]>>();
  const resolveCves = (ghsaId: string): Promise<string[]> => {
    let p = cveCache.get(ghsaId);
    if (p === undefined) {
      p = deps.getCveIds(ghsaId);
      cveCache.set(ghsaId, p);
    }
    return p;
  };

  return Promise.all(
    vulns.map(async (v) => {
      try {
        const cveIds = await resolveCves(v.ghsaId);
        if (cveIds.length === 0) {
          return { ...v, cveIds: [], epss: 0, epssAvailable: false };
        }
        const epssMap = await deps.fetchEpss(cveIds);
        // EPSS(FIRST) は全 CVE を網羅しない。未収載 CVE は応答に現れないため、
        // 「実際にスコアが取れた CVE」だけで判定する。1 件も無ければ epssAvailable=false
        // とし、コメントで取得済み 0 と未取得（—）を区別できるようにする。
        const scored = cveIds.filter((cve) => epssMap[cve] !== undefined);
        const epss = scored.length > 0 ? Math.max(...scored.map((cve) => epssMap[cve]!)) : 0;
        return { ...v, cveIds, epss, epssAvailable: scored.length > 0 };
      } catch {
        // 取得失敗は見逃し方向に倒さず、スコアは CVSS のみで継続させる
        // （epss=0）。失敗は当該 vuln に閉じ込め、全体は止めない。
        return { ...v, cveIds: [], epss: 0, epssAvailable: false };
      }
    }),
  );
}
