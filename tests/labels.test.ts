import { describe, expect, it, vi } from 'vitest';
import { applyBucketLabel } from '../src/labels';
import { parseConfig } from '../src/config';
import type { GithubClient } from '../src/github';
import type { Config } from '../src/types';

function cfg(overrides: Record<string, string> = {}): Config {
  return parseConfig((name) => ({ 'github-token': 'x', ...overrides })[name] ?? '');
}

/** GithubClient モック。現在ラベルを与える。 */
function mockClient(currentLabels: string[]): GithubClient {
  return {
    listIssueComments: vi.fn().mockResolvedValue([]),
    createIssueComment: vi.fn().mockResolvedValue(undefined),
    updateIssueComment: vi.fn().mockResolvedValue(undefined),
    listLabelsOnIssue: vi.fn().mockResolvedValue(currentLabels),
    addLabels: vi.fn().mockResolvedValue(undefined),
    removeLabel: vi.fn().mockResolvedValue(undefined),
    ensureLabelExists: vi.fn().mockResolvedValue(undefined),
  };
}

const HIGH = 'triage:fix-now';
const MID = 'triage:review';
const LOW = 'triage:low-here';

describe('applyBucketLabel', () => {
  it('AC1: high・未付与なら ensureLabelExists(赤) 後に addLabels([labelHigh])', async () => {
    const client = mockClient([]);
    await applyBucketLabel(client, 7, 'high', cfg());
    expect(client.ensureLabelExists).toHaveBeenCalledWith(HIGH, 'd73a4a', expect.any(String));
    expect(client.addLabels).toHaveBeenCalledWith(7, [HIGH]);
  });

  it('AC2: high のとき既存の labelMid/labelLow を removeLabel する', async () => {
    const client = mockClient([MID, LOW]);
    await applyBucketLabel(client, 7, 'high', cfg());
    expect(client.removeLabel).toHaveBeenCalledWith(7, MID);
    expect(client.removeLabel).toHaveBeenCalledWith(7, LOW);
  });

  it('AC3: none は管理ラベルを全て外し addLabels を呼ばない', async () => {
    const client = mockClient([HIGH, MID]);
    await applyBucketLabel(client, 7, 'none', cfg());
    expect(client.removeLabel).toHaveBeenCalledWith(7, HIGH);
    expect(client.removeLabel).toHaveBeenCalledWith(7, MID);
    expect(client.addLabels).not.toHaveBeenCalled();
  });

  it('AC4: 管理外ラベル(bug)は removeLabel の対象にしない', async () => {
    const client = mockClient(['bug', MID]);
    await applyBucketLabel(client, 7, 'high', cfg());
    expect(client.removeLabel).not.toHaveBeenCalledWith(7, 'bug');
    expect(client.removeLabel).toHaveBeenCalledWith(7, MID); // 管理ラベルは外す
  });

  it('AC5: target が既付与なら addLabels せず target を removeLabel もしない(冪等)', async () => {
    const client = mockClient([HIGH]);
    await applyBucketLabel(client, 7, 'high', cfg());
    expect(client.addLabels).not.toHaveBeenCalled();
    expect(client.removeLabel).not.toHaveBeenCalledWith(7, HIGH);
  });

  it('AC6: ensureLabelExists は addLabels より先に呼ばれる', async () => {
    const client = mockClient([]);
    await applyBucketLabel(client, 7, 'mid', cfg());
    const ensureOrder = (client.ensureLabelExists as ReturnType<typeof vi.fn>).mock
      .invocationCallOrder[0]!;
    const addOrder = (client.addLabels as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!;
    expect(ensureOrder).toBeLessThan(addOrder);
    expect(client.ensureLabelExists).toHaveBeenCalledWith(MID, 'fbca04', expect.any(String));
  });

  it('low は緑色で付与する', async () => {
    const client = mockClient([]);
    await applyBucketLabel(client, 7, 'low', cfg());
    expect(client.ensureLabelExists).toHaveBeenCalledWith(LOW, '0e8a16', expect.any(String));
    expect(client.addLabels).toHaveBeenCalledWith(7, [LOW]);
  });

  it('レビュー: 付与(add)を除去(remove)より先に行う（途中失敗で無ラベルにしない）', async () => {
    const client = mockClient([MID]); // high へ付替え: HIGH を add し MID を remove
    await applyBucketLabel(client, 7, 'high', cfg());
    const addOrder = (client.addLabels as ReturnType<typeof vi.fn>).mock.invocationCallOrder[0]!;
    const removeOrder = (client.removeLabel as ReturnType<typeof vi.fn>).mock
      .invocationCallOrder[0]!;
    expect(addOrder).toBeLessThan(removeOrder);
  });
});
