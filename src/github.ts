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

/** octokit を隠蔽するコメント/ラベル CRUD アダプタ。 */
export interface GithubClient {
  listIssueComments(issueNumber: number): Promise<IssueComment[]>;
  createIssueComment(issueNumber: number, body: string): Promise<void>;
  updateIssueComment(commentId: number, body: string): Promise<void>;
  listLabelsOnIssue(issueNumber: number): Promise<string[]>;
  addLabels(issueNumber: number, names: string[]): Promise<void>;
  removeLabel(issueNumber: number, name: string): Promise<void>;
  ensureLabelExists(name: string, color: string, description: string): Promise<void>;
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
  };
}
