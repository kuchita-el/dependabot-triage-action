import type { Config, ScoreResult, Vulnerability } from './types';
import type { GithubClient } from './github';
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

/** 突合確度セル。version=中（バージョン検証済）、name=緩（名前一致のみ）。 */
function confidenceCell(vuln: Vulnerability): string {
  return vuln.matchConfidence === 'version' ? '中' : '緩';
}

/** 脆弱性テーブル（ヘッダ＋各脆弱性 1 行）。 */
function table(vulns: Vulnerability[], config: Config): string {
  const head = '| パッケージ | GHSA | CVE | CVSS | EPSS | スコープ | 確度 | スコア |';
  const sep = '|---|---|---|---|---|---|---|---|';
  const rows = vulns.map((v) => {
    const cells = [
      v.packageName,
      v.ghsaId,
      cveCell(v),
      v.cvss.toFixed(1),
      epssCell(v),
      v.scope,
      confidenceCell(v),
      scoreVulnerability(v, config).toFixed(3),
    ];
    return `| ${cells.join(' | ')} |`;
  });
  return [head, sep, ...rows].join('\n');
}

/**
 * 確度バナー。version（中）を含む場合は解決見込みを示す。
 * 全て name（緩）なら従来の未検証バナーを維持する。
 */
function confidenceBanner(vulns: Vulnerability[]): string {
  const hasVersion = vulns.some((v) => v.matchConfidence === 'version');
  if (hasVersion) {
    return (
      '> ✅ 「中」= このPRの new-version が修正版以上で **解決見込み**（バージョン検証済）。' +
      '「緩」= **このPRが更新するパッケージに紐づく open alert**で、解決は **未検証**（パッケージ名一致のみ・バージョン未確認）。'
    );
  }
  return (
    '> ⚠️ 下表は **このPRが更新するパッケージに紐づく open alert**。' +
    'このPRが解決するかは **未検証**（パッケージ名一致のみ・バージョン未確認）。'
  );
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
      '🟢 通常更新（更新パッケージに紐づく open alert は検出されませんでした）。',
      '',
    ].join('\n');
  }

  return [
    MARKER,
    HEADER,
    '',
    `**判定: \`${result.bucket}\`**（PR スコア ${result.score.toFixed(3)}）`,
    '',
    confidenceBanner(vulns),
    groupNote(config),
    table(vulns, config),
    '',
    footnote(config),
    '',
  ].join('\n');
}

/**
 * トリアージコメントを upsert する。マーカー付き既存コメントがあれば update、
 * 無ければ create。synchronize 再実行でもコメントを増殖させず単一に保つ（F6）。
 */
export async function upsertComment(
  client: GithubClient,
  issueNumber: number,
  body: string,
): Promise<void> {
  const comments = await client.listIssueComments(issueNumber);
  // 本文先頭にマーカーがある自前コメントのみを厳密に同定する。
  // includes だと引用返信（行頭 "> <!-- ... -->"）まで拾い、他者コメントを
  // 上書きしてしまう恐れがあるため startsWith を使う。
  const existing = comments.find((c) => c.body.startsWith(MARKER));
  if (existing) {
    await client.updateIssueComment(existing.id, body);
  } else {
    await client.createIssueComment(issueNumber, body);
  }
}
