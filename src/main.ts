import * as core from '@actions/core';
import * as github from '@actions/github';
import { createGithubClient } from './github';
import { run } from './run';

/**
 * エントリポイント（合成ルート）。実 @actions/core / @actions/github を
 * run() の依存に配線するだけの薄い層。ロジックは run.ts にあり、本ファイルは
 * ユニットテスト対象外（vitest coverage から除外）。
 */
async function main(): Promise<void> {
  const pr = github.context.payload.pull_request;
  if (!pr) {
    core.warning('pull_request イベントではないため no-op で終了');
    return;
  }

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
    makeClient: (token, repo) => createGithubClient(github.getOctokit(token), repo),
  });
}

// run() の内部 try/catch の外で投げられた例外（非 ConfigError 再送出・
// 合成ルートの想定外 throw 等）も握り潰さず、必ず setFailed で締める。
main().catch((err) => core.setFailed(err instanceof Error ? err.message : String(err)));
