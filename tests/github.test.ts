import { describe, expect, it, vi } from 'vitest';
import { createGithubClient } from '../src/github';
import type { GithubOctokit, RepoRef } from '../src/github';

const repo: RepoRef = { owner: 'o', repo: 'r' };

/** 必要な rest.issues.* のみ持つ octokit モックを作る。 */
function mockIssues(overrides: Record<string, ReturnType<typeof vi.fn>> = {}) {
  return {
    listComments: vi.fn().mockResolvedValue({ data: [] }),
    createComment: vi.fn().mockResolvedValue({ data: { id: 1 } }),
    updateComment: vi.fn().mockResolvedValue({ data: { id: 1 } }),
    listLabelsOnIssue: vi.fn().mockResolvedValue({ data: [] }),
    addLabels: vi.fn().mockResolvedValue({ data: [] }),
    removeLabel: vi.fn().mockResolvedValue({ data: [] }),
    getLabel: vi.fn().mockResolvedValue({ data: { name: 'x' } }),
    createLabel: vi.fn().mockResolvedValue({ data: { name: 'x' } }),
    ...overrides,
  };
}

function clientWith(issues: ReturnType<typeof mockIssues>) {
  const octokit = { rest: { issues } } as unknown as GithubOctokit;
  return createGithubClient(octokit, repo);
}

describe('createGithubClient', () => {
  it('AC1: listIssueComments が listComments を呼び {id,body}[] を返す', async () => {
    const issues = mockIssues({
      listComments: vi.fn().mockResolvedValue({
        data: [
          { id: 10, body: 'a' },
          { id: 11, body: undefined },
        ],
      }),
    });
    const result = await clientWith(issues).listIssueComments(42);
    expect(issues.listComments).toHaveBeenCalledWith(
      expect.objectContaining({ owner: 'o', repo: 'r', issue_number: 42 }),
    );
    expect(result).toEqual([
      { id: 10, body: 'a' },
      { id: 11, body: '' },
    ]);
  });

  it('AC2: createIssueComment が createComment を呼ぶ', async () => {
    const issues = mockIssues();
    await clientWith(issues).createIssueComment(42, 'hello');
    expect(issues.createComment).toHaveBeenCalledWith({
      owner: 'o',
      repo: 'r',
      issue_number: 42,
      body: 'hello',
    });
  });

  it('AC3: updateIssueComment が updateComment を呼ぶ', async () => {
    const issues = mockIssues();
    await clientWith(issues).updateIssueComment(99, 'edit');
    expect(issues.updateComment).toHaveBeenCalledWith({
      owner: 'o',
      repo: 'r',
      comment_id: 99,
      body: 'edit',
    });
  });

  it('AC4: listLabelsOnIssue がラベル名の string[] を返す', async () => {
    const issues = mockIssues({
      listLabelsOnIssue: vi.fn().mockResolvedValue({
        data: [{ name: 'triage:fix-now' }, { name: 'bug' }],
      }),
    });
    const result = await clientWith(issues).listLabelsOnIssue(7);
    expect(issues.listLabelsOnIssue).toHaveBeenCalledWith(
      expect.objectContaining({ owner: 'o', repo: 'r', issue_number: 7 }),
    );
    expect(result).toEqual(['triage:fix-now', 'bug']);
  });

  it('AC5: addLabels が addLabels を labels 配列付きで呼ぶ', async () => {
    const issues = mockIssues();
    await clientWith(issues).addLabels(7, ['a', 'b']);
    expect(issues.addLabels).toHaveBeenCalledWith({
      owner: 'o',
      repo: 'r',
      issue_number: 7,
      labels: ['a', 'b'],
    });
  });

  it('AC6: removeLabel が removeLabel を呼ぶ', async () => {
    const issues = mockIssues();
    await clientWith(issues).removeLabel(7, 'old');
    expect(issues.removeLabel).toHaveBeenCalledWith({
      owner: 'o',
      repo: 'r',
      issue_number: 7,
      name: 'old',
    });
  });

  it('AC7: ensureLabelExists は既存(getLabel成功)なら createLabel を呼ばない', async () => {
    const issues = mockIssues();
    await clientWith(issues).ensureLabelExists('triage:fix-now', 'd73a4a', 'desc');
    expect(issues.getLabel).toHaveBeenCalledWith({ owner: 'o', repo: 'r', name: 'triage:fix-now' });
    expect(issues.createLabel).not.toHaveBeenCalled();
  });

  it('AC7: ensureLabelExists は欠如(404)なら createLabel を呼ぶ', async () => {
    const notFound = Object.assign(new Error('Not Found'), { status: 404 });
    const issues = mockIssues({ getLabel: vi.fn().mockRejectedValue(notFound) });
    await clientWith(issues).ensureLabelExists('triage:fix-now', 'd73a4a', 'desc');
    expect(issues.createLabel).toHaveBeenCalledWith({
      owner: 'o',
      repo: 'r',
      name: 'triage:fix-now',
      color: 'd73a4a',
      description: 'desc',
    });
  });

  it('ensureLabelExists は 404 以外のエラーを rethrow し createLabel を呼ばない（silent failure 回避）', async () => {
    const serverErr = Object.assign(new Error('Server Error'), { status: 500 });
    const issues = mockIssues({ getLabel: vi.fn().mockRejectedValue(serverErr) });
    await expect(clientWith(issues).ensureLabelExists('x', 'ffffff', 'd')).rejects.toThrow(
      'Server Error',
    );
    expect(issues.createLabel).not.toHaveBeenCalled();
  });
});
