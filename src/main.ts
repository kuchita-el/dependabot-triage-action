import * as core from '@actions/core';
import * as github from '@actions/github';
import { createGithubClient } from './github';
import { run } from './run';
import type { AdvisoryMeta, EpssDeps } from './epss';

type Octokit = ReturnType<typeof github.getOctokit>;

/**
 * GHSA → advisory メタ（CVE 群＋GitHub 同梱 EPSS）を Global Advisory から解決。
 * CVE は identifiers の CVE、無ければ cve_id。EPSS は epss.percentage（advisory 単位 1 値、
 * optional のため非有限・欠落は null へ）。1 リクエストで CVE と EPSS の両方を取得する。
 */
async function getAdvisory(octokit: Octokit, ghsaId: string): Promise<AdvisoryMeta> {
  const { data } = await octokit.rest.securityAdvisories.getGlobalAdvisory({ ghsa_id: ghsaId });
  const fromIdentifiers = (data.identifiers ?? [])
    .filter((i) => i.type === 'CVE')
    .map((i) => i.value);
  const cveIds = fromIdentifiers.length > 0 ? fromIdentifiers : data.cve_id ? [data.cve_id] : [];
  // epss は REST 応答に同梱されるが octokit の型（plugin-rest-endpoint-methods）が
  // 未反映のため局所的に型を補う（openapi-types には security-advisory-epss として存在）。
  const epss = (data as { epss?: { percentage?: number | null } | null }).epss;
  const pct = epss?.percentage;
  const githubEpss = typeof pct === 'number' && Number.isFinite(pct) ? pct : null;
  return { cveIds, githubEpss };
}

/** CVE 群の EPSS を FIRST API から取得。空は {}、失敗は throw（per-vuln フォールバックに委ねる）。 */
async function fetchEpss(cveIds: string[]): Promise<Record<string, number>> {
  if (cveIds.length === 0) return {};
  const url = `https://api.first.org/data/v1/epss?cve=${cveIds.join(',')}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`EPSS API error: ${res.status}`);
  const json = (await res.json()) as { data?: Array<{ cve: string; epss: string }> };
  const map: Record<string, number> = {};
  for (const row of json.data ?? []) {
    const n = Number(row.epss);
    // 非有限値は map に入れない（未収載扱いに倒し、enrichWithEpss 側で epss=0 に落とす）。
    if (Number.isFinite(n)) map[row.cve] = n;
  }
  return map;
}

/**
 * エントリポイント（合成ルート）。実 @actions/core / @actions/github / HTTP を
 * run() の依存に配線するだけの薄い層。ロジックは run.ts にあり、本ファイルは
 * ユニットテスト対象外（vitest coverage から除外）。
 */
async function main(): Promise<void> {
  const pr = github.context.payload.pull_request;
  if (!pr) {
    core.warning('pull_request イベントではないため no-op で終了');
    return;
  }

  // octokit は 1 インスタンス生成し、client と EPSS の両方で共用する。
  const octokit = github.getOctokit(core.getInput('github-token'));
  const epssDeps: EpssDeps = {
    getAdvisory: (ghsaId) => getAdvisory(octokit, ghsaId),
    fetchEpss,
  };

  await run({
    getInput: (name) => core.getInput(name),
    setOutput: (name, value) => core.setOutput(name, value),
    setFailed: (message) => core.setFailed(message),
    warning: (message) => core.warning(message),
    info: (message) => core.info(message),
    context: {
      repo: github.context.repo,
      prNumber: pr.number,
      actor: (pr.user?.login as string | undefined) ?? github.context.actor,
    },
    makeClient: (_token, repo) => createGithubClient(octokit, repo),
    epssDeps,
  });
}

// run() の内部 try/catch の外で投げられた例外（非 ConfigError 再送出・
// 合成ルートの想定外 throw 等）も握り潰さず、必ず setFailed で締める。
main().catch((err) => core.setFailed(err instanceof Error ? err.message : String(err)));
