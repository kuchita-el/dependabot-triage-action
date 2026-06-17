import { describe, expect, it, vi } from 'vitest';
import { run } from '../src/run';
import type { RunDeps } from '../src/run';
import type { DependabotAlert, GithubClient } from '../src/github';
import type { EpssDeps } from '../src/epss';

function alert(p: Partial<DependabotAlert> = {}): DependabotAlert {
  return {
    ghsaId: 'GHSA-aaaa-bbbb-cccc',
    cveId: 'CVE-2026-0001',
    severity: 'critical',
    cvss: 9.0,
    ecosystem: 'npm',
    packageName: 'left-pad',
    scope: 'runtime',
    firstPatchedVersion: '1.3.0',
    vulnerableVersionRange: '< 1.3.0',
    ...p,
  };
}

function mockClient(overrides: Partial<Record<keyof GithubClient, unknown>> = {}): GithubClient {
  return {
    listIssueComments: vi.fn().mockResolvedValue([]),
    createIssueComment: vi.fn().mockResolvedValue(undefined),
    updateIssueComment: vi.fn().mockResolvedValue(undefined),
    listLabelsOnIssue: vi.fn().mockResolvedValue([]),
    addLabels: vi.fn().mockResolvedValue(undefined),
    removeLabel: vi.fn().mockResolvedValue(undefined),
    ensureLabelExists: vi.fn().mockResolvedValue(undefined),
    listOpenDependabotAlerts: vi.fn().mockResolvedValue([]),
    ...overrides,
  } as GithubClient;
}

/** dependency-names にマッチする open alert を返す client。 */
function securityClient(
  overrides: Partial<Record<keyof GithubClient, unknown>> = {},
): GithubClient {
  return mockClient({
    listOpenDependabotAlerts: vi.fn().mockResolvedValue([alert()]),
    ...overrides,
  });
}

const SECURITY_INPUTS: Record<string, string> = {
  'github-token': 'ghp_x',
  'dependency-names': 'left-pad',
  'package-ecosystem': 'npm',
};

function fakeEpss(): EpssDeps {
  return {
    getAdvisory: vi.fn().mockResolvedValue({ cveIds: ['CVE-2026-0001'], githubEpss: null }),
    fetchEpss: vi.fn().mockResolvedValue({ 'CVE-2026-0001': 0.5 }),
  };
}

function setup(opts: {
  inputs?: Record<string, string>;
  actor?: string;
  client?: GithubClient;
  epssDeps?: EpssDeps;
}) {
  const client = opts.client ?? mockClient();
  const inputs = opts.inputs ?? {};
  const epssDeps = opts.epssDeps ?? fakeEpss();
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
    epssDeps,
  };
  return { deps, client, epssDeps };
}

describe('run', () => {
  it('AC1: 非 dependabot actor は no-op（client/setFailed 未呼び出し）', async () => {
    const { deps } = setup({ inputs: SECURITY_INPUTS, actor: 'someone' });
    await run(deps);
    expect(deps.makeClient).not.toHaveBeenCalled();
    expect(deps.setFailed).not.toHaveBeenCalled();
    expect(deps.info).toHaveBeenCalled();
  });

  it('AC2: マッチする alert ありで reconcile→EPSS→ラベル/コメント/outputs', async () => {
    const { deps, client, epssDeps } = setup({
      inputs: SECURITY_INPUTS,
      client: securityClient(),
    });
    await run(deps);
    expect(client.listOpenDependabotAlerts).toHaveBeenCalled();
    expect(epssDeps.getAdvisory).toHaveBeenCalledWith('GHSA-aaaa-bbbb-cccc'); // EPSS enrich
    expect(client.listLabelsOnIssue).toHaveBeenCalled(); // applyBucketLabel
    expect(client.listIssueComments).toHaveBeenCalled(); // upsertComment
    expect(deps.setOutput).toHaveBeenCalledWith('score', expect.any(String));
    // cvss=9.0/prod + epss=0.5 → (0.6*0.9 + 0.4*0.5)*1.0 = 0.74 → high（EPSS で high が出る）
    expect(deps.setOutput).toHaveBeenCalledWith('bucket', 'high');
    const call = (deps.setOutput as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => c[0] === 'vulnerabilities',
    );
    expect(call).toBeDefined();
    expect(JSON.parse(call![1] as string)).toHaveLength(1);
  });

  it('AC3: alerts 空（または非マッチ）は bucket=none', async () => {
    const { deps } = setup({ inputs: SECURITY_INPUTS }); // 既定 client は alerts 空
    await run(deps);
    expect(deps.setOutput).toHaveBeenCalledWith('bucket', 'none');
  });

  it('AC3: dependency-names に非マッチの alert のみは none', async () => {
    const client = securityClient({
      listOpenDependabotAlerts: vi.fn().mockResolvedValue([alert({ packageName: 'other-pkg' })]),
    });
    const { deps } = setup({ inputs: SECURITY_INPUTS, client });
    await run(deps);
    expect(deps.setOutput).toHaveBeenCalledWith('bucket', 'none');
  });

  it('AC4: listOpenDependabotAlerts 例外 + fail-on-error=false は warning（setFailed 無し）', async () => {
    const client = securityClient({
      listOpenDependabotAlerts: vi.fn().mockRejectedValue(new Error('alerts API down')),
    });
    const { deps } = setup({ inputs: SECURITY_INPUTS, client });
    await run(deps);
    expect(deps.warning).toHaveBeenCalled();
    expect(deps.setFailed).not.toHaveBeenCalled();
  });

  it('AC5: 同例外 + fail-on-error=true は setFailed', async () => {
    const client = securityClient({
      listOpenDependabotAlerts: vi.fn().mockRejectedValue(new Error('alerts API down')),
    });
    const { deps } = setup({ inputs: { ...SECURITY_INPUTS, 'fail-on-error': 'true' }, client });
    await run(deps);
    expect(deps.setFailed).toHaveBeenCalled();
  });

  it('AC6: label=false で applyBucketLabel が呼ばれない', async () => {
    const { deps, client } = setup({
      inputs: { ...SECURITY_INPUTS, label: 'false' },
      client: securityClient(),
    });
    await run(deps);
    expect(client.listLabelsOnIssue).not.toHaveBeenCalled();
    expect(client.addLabels).not.toHaveBeenCalled();
  });

  it('AC6: comment=false で upsertComment が呼ばれない', async () => {
    const { deps, client } = setup({
      inputs: { ...SECURITY_INPUTS, comment: 'false' },
      client: securityClient(),
    });
    await run(deps);
    expect(client.listIssueComments).not.toHaveBeenCalled();
  });

  it('AC7: PAT 欠如(ConfigError)で setFailed', async () => {
    const { deps } = setup({ inputs: { 'dependency-names': 'left-pad' } }); // github-token 無し
    await run(deps);
    expect(deps.setFailed).toHaveBeenCalled();
  });
});
