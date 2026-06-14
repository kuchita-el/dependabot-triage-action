import type { Config, ScoreResult, Vulnerability } from './types';
import { scoreVulnerability } from './score';

/** 既存コメントを識別するためのマーカー（本文先頭に置く）。 */
export const MARKER = '<!-- dependabot-triage -->';

const HEADER = '## 🛡️ Dependabot 脆弱性トリアージ';

export interface RenderInput {
  vulns: Vulnerability[];
  result: ScoreResult;
  config: Config;
}

/** EPSS が未取得ならプレースホルダ、取得済みなら 3 桁表示。 */
function epssCell(vuln: Vulnerability): string {
  return vuln.epssAvailable ? vuln.epss.toFixed(3) : '—';
}

/** CVE は複数連結、無ければプレースホルダ。 */
function cveCell(vuln: Vulnerability): string {
  return vuln.cveIds.length > 0 ? vuln.cveIds.join(', ') : '—';
}

/** グループ PR の注記（非グループは空文字）。 */
function groupNote(config: Config): string {
  if (config.dependencyGroup === '') return '';
  return `\n📦 グループPR: \`${config.dependencyGroup}\`（複数依存をまとめて更新）\n`;
}

/** スコア内訳の脚注（重み・集約・閾値を開示し再現可能にする）。 */
function footnote(config: Config): string {
  return [
    '<sub>',
    'スコア = (w_cvss·cvss/10 + w_epss·epss)·scope。',
    `重み: w_cvss=${config.weightCvss}, w_epss=${config.weightEpss}。`,
    `スコープ係数: prod=${config.scopeProd} / dev=${config.scopeDev} / indirect=${config.scopeIndirect}。`,
    `集約: ${config.aggregate}（PR スコアは [0,1] にクランプ。各行スコアは未クランプの素値）。`,
    `閾値: high≥${config.thresholdHigh}, mid≥${config.thresholdMid}。`,
    '</sub>',
  ].join(' ');
}

/** 脆弱性テーブル（ヘッダ＋各脆弱性 1 行）。 */
function table(vulns: Vulnerability[], config: Config): string {
  const head = '| パッケージ | GHSA | CVE | CVSS | EPSS | スコープ | スコア |';
  const sep = '|---|---|---|---|---|---|---|';
  const rows = vulns.map((v) => {
    const cells = [
      v.packageName,
      v.ghsaId,
      cveCell(v),
      v.cvss.toFixed(1),
      epssCell(v),
      v.scope,
      scoreVulnerability(v, config).toFixed(3),
    ];
    return `| ${cells.join(' | ')} |`;
  });
  return [head, sep, ...rows].join('\n');
}

/**
 * トリアージコメント本文（Markdown）を生成する純粋関数。副作用なし。
 * upsert（既存検索→update/create）は呼び出し側（PR-G）の責務。
 */
export function renderComment(input: RenderInput): string {
  const { vulns, result, config } = input;

  if (result.bucket === 'none' || vulns.length === 0) {
    return [
      MARKER,
      HEADER,
      '',
      '🟢 通常更新（このPRが解決する既知の脆弱性は検出されませんでした）。',
      '',
    ].join('\n');
  }

  return [
    MARKER,
    HEADER,
    '',
    `**判定: \`${result.bucket}\`**（PR スコア ${result.score.toFixed(3)}）`,
    groupNote(config),
    table(vulns, config),
    '',
    footnote(config),
    '',
  ].join('\n');
}
