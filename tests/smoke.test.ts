import { describe, expect, it } from 'vitest';

/**
 * 雛形のスモークテスト。テストランナー（Vitest）が起動し、TS を解釈し、
 * 最低 1 本が pass することを確認する。ドメインロジックのテストは PR-B 以降。
 */
describe('scaffold smoke', () => {
  it('Vitest が TypeScript テストを実行できる', () => {
    expect(1 + 1).toBe(2);
  });
});
