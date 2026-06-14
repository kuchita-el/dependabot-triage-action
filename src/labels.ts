import type { Bucket, Config } from './types';
import type { GithubClient } from './github';

/** バケットごとのラベル色（固定）。 */
const COLORS = { high: 'd73a4a', mid: 'fbca04', low: '0e8a16' } as const;

/** このActionが作成する管理ラベルの説明。 */
const LABEL_DESCRIPTION = 'Dependabot 脆弱性トリアージのバケット（このActionが管理）';

interface LabelSpec {
  name: string;
  color: string;
}

/** バケットから付与すべきラベル仕様を返す。none は付与なし。 */
function targetLabel(bucket: Bucket, config: Config): LabelSpec | null {
  switch (bucket) {
    case 'high':
      return { name: config.labelHigh, color: COLORS.high };
    case 'mid':
      return { name: config.labelMid, color: COLORS.mid };
    case 'low':
      return { name: config.labelLow, color: COLORS.low };
    case 'none':
      return null;
  }
}

/**
 * バケットに応じて管理ラベルを 1 つだけ付与する。
 * 管理ラベル群 = [labelHigh, labelMid, labelLow]。該当しない管理ラベルは外し、
 * 管理外（他人が付けた）ラベルには触れない。none はラベル無し。
 */
export async function applyBucketLabel(
  client: GithubClient,
  issueNumber: number,
  bucket: Bucket,
  config: Config,
): Promise<void> {
  const managed = [config.labelHigh, config.labelMid, config.labelLow];
  const target = targetLabel(bucket, config);
  const current = await client.listLabelsOnIssue(issueNumber);

  // 管理ラベルのうち target 以外を外す（管理外ラベルは対象にしない）。
  for (const name of managed) {
    if (name !== target?.name && current.includes(name)) {
      await client.removeLabel(issueNumber, name);
    }
  }

  // target が未付与なら、存在を保証してから付与する。
  if (target && !current.includes(target.name)) {
    await client.ensureLabelExists(target.name, target.color, LABEL_DESCRIPTION);
    await client.addLabels(issueNumber, [target.name]);
  }
}
