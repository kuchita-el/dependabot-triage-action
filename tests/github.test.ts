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

/** 既定の paginate: 実 octokit と同様、route を呼んでデータ配列を返すよう委譲する。 */
function defaultPaginate() {
  return vi.fn(async (route: (p: unknown) => Promise<{ data: unknown[] }>, params: unknown) => {
    const res = await route(params);
    return res.data;
  });
}

function makeClient(
  issues: ReturnType<typeof mockIssues>,
  paginate: ReturnType<typeof vi.fn> = defaultPaginate(),
) {
  const octokit = { rest: { issues }, paginate } as unknown as GithubOctokit;
  return createGithubClient(octokit, repo);
}

function clientWith(issues: ReturnType<typeof mockIssues>) {
  return makeClient(issues);
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

  it('レビュー: listIssueComments は paginate で全ページ取得する（101件超でも欠落しない）', async () => {
    const many = Array.from({ length: 150 }, (_, i) => ({ id: i, body: `c${i}` }));
    const paginate = vi.fn().mockResolvedValue(many);
    const client = makeClient(mockIssues(), paginate);
    const result = await client.listIssueComments(1);
    expect(paginate).toHaveBeenCalledTimes(1);
    expect(result).toHaveLength(150);
    expect(result[149]).toEqual({ id: 149, body: 'c149' });
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

/** Dependabot alert の生レスポンス（最小）。 */
function rawAlert(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    security_advisory: {
      ghsa_id: 'GHSA-xxxx-yyyy-zzzz',
      cve_id: 'CVE-2026-0001',
      severity: 'high',
      cvss: { score: 7.5 },
      cvss_severities: { cvss_v4: { score: 8.1 } },
    },
    security_vulnerability: {
      package: { ecosystem: 'npm', name: 'left-pad' },
      first_patched_version: { identifier: '1.3.0' },
      vulnerable_version_range: '< 1.3.0',
    },
    dependency: { scope: 'runtime' },
    ...overrides,
  };
}

function alertsClient(alerts: Array<Record<string, unknown>>) {
  const listAlertsForRepo = vi.fn().mockResolvedValue({ data: alerts });
  const paginate = vi.fn(
    async (route: (p: unknown) => Promise<{ data: unknown[] }>, params: unknown) =>
      (await route(params)).data,
  );
  const octokit = {
    rest: { dependabot: { listAlertsForRepo }, issues: {} },
    paginate,
  } as unknown as GithubOctokit;
  return { client: createGithubClient(octokit, repo), listAlertsForRepo, paginate };
}

describe('listOpenDependabotAlerts', () => {
  it('AC1: paginate で listAlertsForRepo を state=open 付きで呼ぶ', async () => {
    const { client, paginate, listAlertsForRepo } = alertsClient([]);
    await client.listOpenDependabotAlerts();
    expect(paginate).toHaveBeenCalledWith(
      listAlertsForRepo,
      expect.objectContaining({ owner: 'o', repo: 'r', state: 'open' }),
    );
  });

  it('AC2: alert を DependabotAlert に正規化する', async () => {
    const { client } = alertsClient([rawAlert()]);
    const [a] = await client.listOpenDependabotAlerts();
    expect(a).toEqual({
      ghsaId: 'GHSA-xxxx-yyyy-zzzz',
      cveId: 'CVE-2026-0001',
      severity: 'high',
      cvss: 8.1, // max(v3=7.5, v4=8.1)
      ecosystem: 'npm',
      packageName: 'left-pad',
      scope: 'runtime',
      firstPatchedVersion: '1.3.0',
      vulnerableVersionRange: '< 1.3.0',
    });
  });

  it('AC3: cvss は v3/v4 の max / 片方のみはその値 / どちらも無しは 0', async () => {
    // v4 > v3 → v4
    const v4 = alertsClient([rawAlert()]);
    expect((await v4.client.listOpenDependabotAlerts())[0]!.cvss).toBe(8.1);

    // v3 > v4 → v3（max が高い方を採る）
    const v3hi = alertsClient([
      rawAlert({
        security_advisory: {
          ghsa_id: 'G',
          cve_id: null,
          severity: 'high',
          cvss: { score: 8.1 },
          cvss_severities: { cvss_v4: { score: 2.0 } },
        },
      }),
    ]);
    expect((await v3hi.client.listOpenDependabotAlerts())[0]!.cvss).toBe(8.1);

    // v4 ベクタ未保有（score=0）+ v3 実値 → v3（??では 0 に化けた回帰ケース）
    const v4zero = alertsClient([
      rawAlert({
        security_advisory: {
          ghsa_id: 'G',
          cve_id: null,
          severity: 'high',
          cvss: { score: 8.1 },
          cvss_severities: { cvss_v4: { score: 0 } },
        },
      }),
    ]);
    expect((await v4zero.client.listOpenDependabotAlerts())[0]!.cvss).toBe(8.1);

    // v3 のみ（cvss_severities 無し） → v3
    const v3 = alertsClient([
      rawAlert({
        security_advisory: { ghsa_id: 'G', cve_id: null, severity: 'low', cvss: { score: 4.2 } },
      }),
    ]);
    expect((await v3.client.listOpenDependabotAlerts())[0]!.cvss).toBe(4.2);

    // どちらも無し → 0
    const none = alertsClient([
      rawAlert({ security_advisory: { ghsa_id: 'G', cve_id: null, severity: 'low' } }),
    ]);
    expect((await none.client.listOpenDependabotAlerts())[0]!.cvss).toBe(0);
  });

  it('AC4: ページングの全件を返す', async () => {
    const { client } = alertsClient([rawAlert(), rawAlert(), rawAlert()]);
    expect(await client.listOpenDependabotAlerts()).toHaveLength(3);
  });

  it('AC5: cve_id / first_patched_version 欠落は null', async () => {
    const { client } = alertsClient([
      rawAlert({
        security_advisory: { ghsa_id: 'G', cve_id: null, severity: 'low', cvss: { score: 1 } },
        security_vulnerability: {
          package: { ecosystem: 'pip', name: 'requests' },
          vulnerable_version_range: '>= 0',
        },
        dependency: {},
      }),
    ]);
    const [a] = await client.listOpenDependabotAlerts();
    expect(a!.cveId).toBeNull();
    expect(a!.firstPatchedVersion).toBeNull();
    expect(a!.scope).toBeNull();
  });
});
