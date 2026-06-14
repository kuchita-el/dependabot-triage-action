import type { getOctokit } from '@actions/github';

/** @actions/github の getOctokit が返す型。アダプタが内部で依存する octokit。 */
export type GithubOctokit = ReturnType<typeof getOctokit>;

/** 対象リポジトリ。 */
export interface RepoRef {
  owner: string;
  repo: string;
}

/** コメントの最小表現。 */
export interface IssueComment {
  id: number;
  body: string;
}

/** 突合（M2-2）に必要なフィールドへ正規化した Dependabot alert。 */
export interface DependabotAlert {
  ghsaId: string;
  cveId: string | null;
  severity: string;
  /** CVSS（v4 優先・無ければ v3・どちらも無ければ 0）。 */
  cvss: number;
  ecosystem: string;
  packageName: string;
  /** 'runtime' | 'development' | null。 */
  scope: string | null;
  firstPatchedVersion: string | null;
  vulnerableVersionRange: string;
}

/** octokit の alert レスポンス（型に無い v4 フィールドへ防御的アクセスするための最小形）。 */
interface RawAlert {
  security_advisory?: {
    ghsa_id?: string;
    cve_id?: string | null;
    severity?: string;
    cvss?: { score?: number | null } | null;
    cvss_severities?: { cvss_v4?: { score?: number | null } | null } | null;
  } | null;
  security_vulnerability?: {
    package?: { ecosystem?: string; name?: string } | null;
    first_patched_version?: { identifier?: string } | null;
    vulnerable_version_range?: string;
  } | null;
  dependency?: { scope?: string | null } | null;
}

/** 生 alert を DependabotAlert へ正規化。cvss は v4 優先で防御的に取る。 */
function normalizeAlert(raw: RawAlert): DependabotAlert {
  const adv = raw.security_advisory ?? {};
  const vuln = raw.security_vulnerability ?? {};
  const cvss = adv.cvss_severities?.cvss_v4?.score ?? adv.cvss?.score ?? 0;
  return {
    ghsaId: adv.ghsa_id ?? '',
    cveId: adv.cve_id ?? null,
    severity: adv.severity ?? '',
    cvss,
    ecosystem: vuln.package?.ecosystem ?? '',
    packageName: vuln.package?.name ?? '',
    scope: raw.dependency?.scope ?? null,
    firstPatchedVersion: vuln.first_patched_version?.identifier ?? null,
    vulnerableVersionRange: vuln.vulnerable_version_range ?? '',
  };
}

/** octokit を隠蔽するコメント/ラベル CRUD アダプタ。 */
export interface GithubClient {
  listIssueComments(issueNumber: number): Promise<IssueComment[]>;
  createIssueComment(issueNumber: number, body: string): Promise<void>;
  updateIssueComment(commentId: number, body: string): Promise<void>;
  listLabelsOnIssue(issueNumber: number): Promise<string[]>;
  addLabels(issueNumber: number, names: string[]): Promise<void>;
  removeLabel(issueNumber: number, name: string): Promise<void>;
  ensureLabelExists(name: string, color: string, description: string): Promise<void>;
  listOpenDependabotAlerts(): Promise<DependabotAlert[]>;
}

/** エラーが HTTP 404（未検出）か。 */
function isNotFound(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { status?: number }).status === 404;
}

/**
 * octokit と repo を注入してアダプタを生成する。
 * ドメイン層は octokit を直接触らず本クライアント経由で操作する（依存隠蔽）。
 */
export function createGithubClient(octokit: GithubOctokit, repo: RepoRef): GithubClient {
  const { owner, repo: name } = repo;
  const base = { owner, repo: name };

  return {
    async listIssueComments(issueNumber) {
      // ページング全件取得。マーカー検索（PR-G の upsert）が 2 ページ目以降を
      // 取りこぼすとコメント重複につながるため paginate を使う。
      const comments = await octokit.paginate(octokit.rest.issues.listComments, {
        ...base,
        issue_number: issueNumber,
        per_page: 100,
      });
      return comments.map((c) => ({ id: c.id, body: c.body ?? '' }));
    },

    async createIssueComment(issueNumber, body) {
      await octokit.rest.issues.createComment({ ...base, issue_number: issueNumber, body });
    },

    async updateIssueComment(commentId, body) {
      await octokit.rest.issues.updateComment({ ...base, comment_id: commentId, body });
    },

    async listLabelsOnIssue(issueNumber) {
      const labels = await octokit.paginate(octokit.rest.issues.listLabelsOnIssue, {
        ...base,
        issue_number: issueNumber,
        per_page: 100,
      });
      return labels.map((l) => l.name);
    },

    async addLabels(issueNumber, names) {
      await octokit.rest.issues.addLabels({ ...base, issue_number: issueNumber, labels: names });
    },

    async removeLabel(issueNumber, labelName) {
      await octokit.rest.issues.removeLabel({
        ...base,
        issue_number: issueNumber,
        name: labelName,
      });
    },

    async ensureLabelExists(labelName, color, description) {
      try {
        await octokit.rest.issues.getLabel({ ...base, name: labelName });
      } catch (err) {
        // 未検出（404）のときだけ作成。それ以外（認可・サーバエラー等）は
        // 握り潰さず rethrow して silent failure を防ぐ。
        if (isNotFound(err)) {
          await octokit.rest.issues.createLabel({ ...base, name: labelName, color, description });
          return;
        }
        throw err;
      }
    },

    async listOpenDependabotAlerts() {
      const alerts = await octokit.paginate(octokit.rest.dependabot.listAlertsForRepo, {
        ...base,
        state: 'open',
        per_page: 100,
      });
      return (alerts as RawAlert[]).map(normalizeAlert);
    },
  };
}
