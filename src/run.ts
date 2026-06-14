import { ConfigError, parseConfig } from './config';
import { collectM1Vulnerabilities } from './metadata';
import { evaluate } from './score';
import { applyBucketLabel } from './labels';
import { renderComment, upsertComment } from './comment';
import type { GithubClient } from './github';

/** Dependabot の bot アクター名。これ以外の PR は対象外。 */
const DEPENDABOT_ACTOR = 'dependabot[bot]';

export interface RunContext {
  repo: { owner: string; repo: string };
  prNumber: number;
  actor: string;
}

/** run() の依存。実 @actions/* は main.ts が注入する（DI でテスト可能にする）。 */
export interface RunDeps {
  getInput: (name: string) => string;
  setOutput: (name: string, value: string) => void;
  setFailed: (message: string) => void;
  warning: (message: string) => void;
  info: (message: string) => void;
  context: RunContext;
  makeClient: (token: string, repo: { owner: string; repo: string }) => GithubClient;
}

/**
 * オーケストレーション本体。ガード→config→metadata→score→ラベル/コメント→outputs。
 * 設定不備（ConfigError）は常に setFailed。トリアージ失敗は fail-on-error で
 * setFailed / warning を切り替え、既定では PR をブロックしない。
 */
export async function run(deps: RunDeps): Promise<void> {
  const { context } = deps;

  // (1) ガード: Dependabot 以外の PR は no-op で正常終了。
  if (context.actor !== DEPENDABOT_ACTOR) {
    deps.info(`actor=${context.actor} は Dependabot ではないため no-op で終了`);
    return;
  }

  // (2) 設定パース。設定不備は fail-on-error に依らず setFailed。
  let config;
  try {
    config = parseConfig(deps.getInput);
  } catch (err) {
    if (err instanceof ConfigError) {
      deps.setFailed(err.message);
      return;
    }
    throw err;
  }

  // (3)〜(8) トリアージ本体。失敗は fail-on-error で切替。
  try {
    const vulns = collectM1Vulnerabilities(config);
    const result = evaluate(vulns, config);

    // outputs はラベル/コメント（副作用）より先に出す。スコアは決定論的に
    // 算出済みのため、publish（API）が失敗しても結果を下流ジョブへ渡せる。
    deps.setOutput('score', String(result.score));
    deps.setOutput('bucket', result.bucket);
    deps.setOutput('vulnerabilities', JSON.stringify(vulns));

    const client = deps.makeClient(config.githubToken, context.repo);
    if (config.label) {
      await applyBucketLabel(client, context.prNumber, result.bucket, config);
    }
    if (config.comment) {
      const body = renderComment({ vulns, result, config });
      await upsertComment(client, context.prNumber, body);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (config.failOnError) {
      deps.setFailed(`トリアージに失敗: ${message}`);
    } else {
      deps.warning(`トリアージに失敗（PR はブロックしない）: ${message}`);
    }
  }
}
