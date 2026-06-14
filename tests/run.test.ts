import { describe, expect, it, vi } from 'vitest';
import { run } from '../src/run';
import type { RunDeps } from '../src/run';
import type { GithubClient } from '../src/github';

function mockClient(overrides: Partial<Record<keyof GithubClient, unknown>> = {}): GithubClient {
  return {
    listIssueComments: vi.fn().mockResolvedValue([]),
    createIssueComment: vi.fn().mockResolvedValue(undefined),
    updateIssueComment: vi.fn().mockResolvedValue(undefined),
    listLabelsOnIssue: vi.fn().mockResolvedValue([]),
    addLabels: vi.fn().mockResolvedValue(undefined),
    removeLabel: vi.fn().mockResolvedValue(undefined),
    ensureLabelExists: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as GithubClient;
}

const SECURITY_INPUTS: Record<string, string> = {
  'github-token': 'ghp_x',
  'alert-ghsa-id': 'GHSA-aaaa-bbbb-cccc',
  'alert-cvss': '9.0',
  'dependency-names': 'left-pad',
  'package-ecosystem': 'npm',
  'dependency-type': 'direct:production',
};

function setup(opts: { inputs?: Record<string, string>; actor?: string; client?: GithubClient }) {
  const client = opts.client ?? mockClient();
  const inputs = opts.inputs ?? {};
  const deps: RunDeps = {
    getInput: (name) => inputs[name] ?? '',
    setOutput: vi.fn(),
    setFailed: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
    context: {
      repo: { owner: 'o', repo: 'r' },
      prNumber: 7,
      actor: opts.actor ?? 'dependabot[bot]',
    },
    makeClient: vi.fn(() => client),
  };
  return { deps, client };
}

describe('run', () => {
  it('AC1: 非 dependabot actor は no-op（client/setFailed 未呼び出し）', async () => {
    const { deps } = setup({ inputs: SECURITY_INPUTS, actor: 'someone' });
    await run(deps);
    expect(deps.makeClient).not.toHaveBeenCalled();
    expect(deps.setFailed).not.toHaveBeenCalled();
    expect(deps.info).toHaveBeenCalled();
  });

  it('AC2: dependabot+セキュリティ更新でラベル/コメント/outputs が実行される', async () => {
    const { deps, client } = setup({ inputs: SECURITY_INPUTS });
    await run(deps);
    expect(client.listLabelsOnIssue).toHaveBeenCalled(); // applyBucketLabel 経由
    expect(client.listIssueComments).toHaveBeenCalled(); // upsertComment 経由
    expect(deps.setOutput).toHaveBeenCalledWith('score', expect.any(String));
    // M1 は EPSS=0 のため cvss=9.0/prod でも score=0.54 → mid（high ではない）
    expect(deps.setOutput).toHaveBeenCalledWith('bucket', 'mid');
    const call = (deps.setOutput as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => c[0] === 'vulnerabilities',
    );
    expect(call).toBeDefined();
    expect(() => JSON.parse(call![1] as string)).not.toThrow();
    expect(JSON.parse(call![1] as string)).toHaveLength(1);
  });

  it('AC3: label=false で applyBucketLabel が呼ばれない', async () => {
    const { deps, client } = setup({ inputs: { ...SECURITY_INPUTS, label: 'false' } });
    await run(deps);
    expect(client.listLabelsOnIssue).not.toHaveBeenCalled();
    expect(client.addLabels).not.toHaveBeenCalled();
  });

  it('AC4: comment=false で upsertComment が呼ばれない', async () => {
    const { deps, client } = setup({ inputs: { ...SECURITY_INPUTS, comment: 'false' } });
    await run(deps);
    expect(client.listIssueComments).not.toHaveBeenCalled();
  });

  it('AC5: PAT 欠如(ConfigError)で setFailed', async () => {
    const { deps } = setup({ inputs: { 'alert-ghsa-id': 'GHSA-x' } }); // github-token 無し
    await run(deps);
    expect(deps.setFailed).toHaveBeenCalled();
  });

  it('AC6: トリアージ例外 + fail-on-error=false は warning（setFailed 無し）', async () => {
    const client = mockClient({
      listLabelsOnIssue: vi.fn().mockRejectedValue(new Error('API down')),
    });
    const { deps } = setup({ inputs: SECURITY_INPUTS, client });
    await run(deps);
    expect(deps.warning).toHaveBeenCalled();
    expect(deps.setFailed).not.toHaveBeenCalled();
  });

  it('AC7: トリアージ例外 + fail-on-error=true は setFailed', async () => {
    const client = mockClient({
      listLabelsOnIssue: vi.fn().mockRejectedValue(new Error('API down')),
    });
    const { deps } = setup({ inputs: { ...SECURITY_INPUTS, 'fail-on-error': 'true' }, client });
    await run(deps);
    expect(deps.setFailed).toHaveBeenCalled();
  });

  it('AC8: 非セキュリティ更新(空vulns)は bucket=none', async () => {
    const { deps } = setup({ inputs: { 'github-token': 'ghp_x' } }); // alert 情報なし
    await run(deps);
    expect(deps.setOutput).toHaveBeenCalledWith('bucket', 'none');
  });
});
