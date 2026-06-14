import { describe, expect, it } from 'vitest';
import { renderComment, MARKER } from '../src/comment';
import { evaluate } from '../src/score';
import { parseConfig } from '../src/config';
import type { Config, Vulnerability } from '../src/types';

function cfg(overrides: Record<string, string> = {}): Config {
  return parseConfig((name) => ({ 'github-token': 'x', ...overrides })[name] ?? '');
}

function vuln(p: Partial<Vulnerability> = {}): Vulnerability {
  return {
    ghsaId: 'GHSA-aaaa-bbbb-cccc',
    cveIds: ['CVE-2026-0001'],
    cvss: 9.0,
    epss: 0.5,
    epssAvailable: true,
    severity: 'high',
    packageName: 'pkg',
    ecosystem: 'npm',
    scope: 'direct:production',
    ...p,
  };
}

/** vulns から result を作り renderComment を呼ぶ。 */
function render(vulns: Vulnerability[], overrides: Record<string, string> = {}): string {
  const config = cfg(overrides);
  return renderComment({ vulns, result: evaluate(vulns, config), config });
}

/** テーブルのデータ行（ヘッダ・区切りを除く）を返す。 */
function dataRows(out: string): string[] {
  return out
    .split('\n')
    .filter((l) => l.trimStart().startsWith('|'))
    .filter((l) => !l.includes('パッケージ') && !/^\s*\|[\s|:-]+\|?\s*$/.test(l));
}

describe('renderComment', () => {
  it('AC1: 出力はマーカーで始まる', () => {
    expect(render([vuln()]).startsWith(MARKER)).toBe(true);
    expect(MARKER).toBe('<!-- dependabot-triage -->');
  });

  it('AC2: 非セキュリティ更新(空vulns)は通常更新メッセージかつテーブルなし', () => {
    const out = render([]);
    expect(out).toMatch(/通常更新/);
    expect(out).not.toContain('| パッケージ |');
  });

  it('AC3: 単一脆弱性はパッケージ/GHSA/CVSS/スコアを含む行を持つ', () => {
    const out = render([
      vuln({ packageName: 'left-pad', ghsaId: 'GHSA-xxxx-yyyy-zzzz', cvss: 9.0 }),
    ]);
    const rows = dataRows(out);
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row).toContain('left-pad');
    expect(row).toContain('GHSA-xxxx-yyyy-zzzz');
    expect(row).toContain('9.0'); // CVSS
    expect(row).toContain('0.740'); // この脆弱性のスコア
  });

  it('AC4: N件の脆弱性はN行になる', () => {
    const out = render([
      vuln({ ghsaId: 'GHSA-1111-1111-1111', packageName: 'a' }),
      vuln({ ghsaId: 'GHSA-2222-2222-2222', packageName: 'b' }),
      vuln({ ghsaId: 'GHSA-3333-3333-3333', packageName: 'c' }),
    ]);
    expect(dataRows(out)).toHaveLength(3);
  });

  it('AC5: epssAvailable=false は EPSS 欄がプレースホルダ「—」（数値でない）', () => {
    const out = render([vuln({ epss: 0, epssAvailable: false })]);
    const row = dataRows(out)[0]!;
    expect(row).toContain('—');
    expect(row).not.toContain('0.000');
  });

  it('AC5: epssAvailable=true は EPSS 欄が数値', () => {
    const out = render([vuln({ epss: 0.5, epssAvailable: true })]);
    expect(dataRows(out)[0]!).toContain('0.500');
  });

  it('AC6: 脚注に重み・集約方式・閾値が開示される', () => {
    const out = render([vuln()]);
    expect(out).toContain('0.6'); // weightCvss
    expect(out).toContain('0.4'); // weightEpss
    expect(out).toContain('max'); // aggregate
    expect(out).toContain('0.66'); // thresholdHigh
    expect(out).toContain('0.33'); // thresholdMid
  });

  it('レビュー: 脚注に PR スコアの [0,1] クランプを開示する（行スコアとの不一致説明）', () => {
    const out = render([vuln()]);
    expect(out).toMatch(/クランプ/);
    expect(out).toContain('[0,1]');
  });

  it('AC7: グループPRは注記が出る', () => {
    const out = render([vuln()], { 'dependency-group': 'prod-deps' });
    expect(out).toContain('prod-deps');
    expect(out).toMatch(/グループ/);
  });

  it('CVE 欠損は「—」を表示', () => {
    const out = render([vuln({ cveIds: [] })]);
    expect(dataRows(out)[0]!).toContain('—');
  });
});
