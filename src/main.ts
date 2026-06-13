import * as core from '@actions/core';

/**
 * エントリポイント。実体のオーケストレーション（run()）は PR-G で実装する。
 * 本 PR（PR-A）は雛形のため、起動可能なスタブに留める。
 */
async function main(): Promise<void> {
  core.debug('dependabot-triage: scaffold entrypoint (no-op until PR-G)');
}

void main();
