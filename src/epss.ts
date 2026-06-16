import type { Vulnerability } from './types';

/** GHSA advisory のメタ（CVE 群と GitHub 同梱の EPSS）。 */
export interface AdvisoryMeta {
  /** GHSA に紐づく CVE ID 群（0 件以上）。 */
  cveIds: string[];
  /**
   * GitHub Advisory に同梱される EPSS（epss.percentage, 0..1）。
   * advisory 単位で 1 値。無い場合（CVE 未割当・未収載等）は null。
   */
  githubEpss: number | null;
}

/**
 * EPSS 取得の外部依存。実 octokit/HTTP は main.ts（合成ルート）が注入する。
 * - getAdvisory: GHSA ID → CVE 群＋GitHub 同梱 EPSS（getGlobalAdvisory 相当、1 回で両方取得）
 * - fetchEpss: CVE 群 → CVE ごとの EPSS スコア（FIRST EPSS API 相当、GitHub 不明時の補完）
 */
export interface EpssDeps {
  getAdvisory: (ghsaId: string) => Promise<AdvisoryMeta>;
  fetchEpss: (cveIds: string[]) => Promise<Record<string, number>>;
}

/**
 * 脆弱性集合に EPSS を付与する（GitHub 優先 + FIRST 補完）。各 vuln の GHSA から
 * advisory メタ（CVE 群＋GitHub EPSS）を解決し:
 * - GitHub EPSS（advisory 単位 1 値）が有限ならそれを採用（FIRST は呼ばない）
 * - 無ければ CVE 群を FIRST へ問い合わせ、複数 CVE の max（最悪ケース駆動）
 * - CVE 無し・取得失敗時は当該 vuln のみ epss=0 / epssAvailable=false にフォールバックし、
 *   他 vuln の処理は止めない。
 *
 * GHSA→advisory はメモ化（同一 GHSA の重複取得を避ける）。fetchEpss は per-vuln の
 * 失敗分離を優先して跨 vuln メモ化しない（vuln は GHSA で一意のため実益も小さい）。
 * 入力 vulns は破壊せず新オブジェクトを返す。
 */
export async function enrichWithEpss(
  vulns: Vulnerability[],
  deps: EpssDeps,
): Promise<Vulnerability[]> {
  // GHSA→advisory の Promise メモ化（並列でも 1 GHSA 1 回）。
  const advisoryCache = new Map<string, Promise<AdvisoryMeta>>();
  const resolveAdvisory = (ghsaId: string): Promise<AdvisoryMeta> => {
    let p = advisoryCache.get(ghsaId);
    if (p === undefined) {
      p = deps.getAdvisory(ghsaId);
      advisoryCache.set(ghsaId, p);
    }
    return p;
  };

  return Promise.all(
    vulns.map(async (v) => {
      try {
        const { cveIds, githubEpss } = await resolveAdvisory(v.ghsaId);
        // GitHub 同梱 EPSS を優先（advisory 単位で畳み済み。0 も有効値として採用）。
        // 非有限値（異常応答の NaN 等）は採用せず FIRST フォールバックへ倒す。
        if (githubEpss !== null && Number.isFinite(githubEpss)) {
          return { ...v, cveIds, epss: githubEpss, epssAvailable: true };
        }
        if (cveIds.length === 0) {
          return { ...v, cveIds: [], epss: 0, epssAvailable: false };
        }
        const epssMap = await deps.fetchEpss(cveIds);
        // EPSS(FIRST) は全 CVE を網羅しない。未収載 CVE は応答に現れないため、
        // 「実際に有限スコアが取れた CVE」だけで判定する。非有限値（異常応答の NaN 等）も
        // 未収載扱いに倒し、evaluate へ非有限を伝播させない（無出力縮退の防止）。
        // 1 件も無ければ epssAvailable=false とし、取得済み 0 と未取得（—）を区別する。
        const scored = cveIds.filter((cve) => Number.isFinite(epssMap[cve]));
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
