# 設計合意 — Dependabot 脆弱性トリアージ Action

> 開発ブリーフ（依頼仕様）を受けた合意事項。後続 PR はこのドキュメントを基準とする。
> ブリーフからの逸脱は本文に明記する。

## スコープ

Dependabot PR の脆弱性を「このリポジトリ基準の深刻度」へ畳み込み、(1) ラベル 1 つ付与、
(2) 単一コメントを upsert する GitHub Action。`pull_request_target` で動作、PR コードは checkout/実行しない。

## ブリーフからの逸脱

| 項目 | ブリーフ | 本プロジェクト | 理由 |
|---|---|---|---|
| Node ランタイム | Node 20 | **Node 24** (`using: 'node24'`) | GHA ランナーは 2026-06-02 以降 node24 既定、2026-09-16 に node20 削除。node20 で作ると公開後すぐ動かなくなる |
| モジュール構成 | （octokit を各所から） | **`github.ts` アダプタを追加**し octokit を隠蔽 | ブリーフの「依存隠蔽」原則の徹底 |

## ツールチェーン

- パッケージ管理: npm（GitHub Action JS の慣習・dist コミット・ncc と相性）
- Node: mise で 24 を固定（`mise.toml`、ホスト非汚染・可逆）
- バンドル: `@vercel/ncc`、`dist/` をコミット
- テスト: Vitest（GitHub API / EPSS API は必ずモック、ネットワークに出ない）
- リポジトリ: 1 Action = 1 repo。GitHub repo 名 `dependabot-triage-action`（Marketplace はリポジトリ直下 action.yml のみ対象）

## モジュール責務

| モジュール | 責務 | 純粋性 | テスト |
|---|---|---|---|
| `main.ts` | エントリ。`run()` を呼ぶだけ | - | 不要 |
| `run.ts` | オーケストレーション | 副作用集約 | 統合（mock） |
| `config.ts` | inputs パース・既定値・PAT 必須チェック | 純粋寄り | 単体 |
| `metadata.ts` | fetch-metadata 出力の受取 + alerts 突合 | アダプタ | 突合純粋部を単体 |
| `epss.ts` | GHSA→CVE→EPSS。並列・メモ化・失敗時 0 | アダプタ | mock |
| `score.ts` | スコア計算・集約・バケット判定 | **純粋** | 単体（網羅） |
| `comment.ts` | 本文生成（純粋）+ upsert（副作用） | 分離 | 生成=単体 / upsert=mock |
| `labels.ts` | バケット→ラベル付替え | アダプタ | mock |
| `github.ts` | octokit を隠す薄いアダプタ（alerts ページング・コメント/ラベル CRUD） | アダプタ | mock |
| `types.ts` | 共有型 | - | - |

## データフロー

```
run()
 ├─ config.parse(inputs)                    # PAT 欠如なら setFailed で即停止
 ├─ guard: actor == 'dependabot[bot]' ?     # 否なら no-op 正常終了
 ├─ metadata.collect()
 │    ├─ M1: fetch-metadata 出力(inputs経由)をそのまま脆弱性1件に
 │    └─ M2: + GET /dependabot/alerts?state=open (ページング) を突合
 ├─ epss.enrich(vulns)                       # GHSA→CVE→EPSS, 失敗時 epss=0
 ├─ score.evaluate(vulns, config)            # 各score→集約(max)→bucket
 ├─ if config.label:   labels.apply(bucket)  # 管理ラベル群を付替え
 ├─ if config.comment: comment.upsert(body)  # マーカーで update/create
 └─ setOutput(score, bucket, vulnerabilities)
```

## スコア（F4）

```
score(v) = (w_cvss · cvss/10 + w_epss · epss) · scope(depType)
既定: w_cvss=0.6, w_epss=0.4, scope: prod=1.0 / dev=0.4 / indirect=0.7
PR 全体スコア = 各脆弱性スコアの集約（既定 max、sum は M3）
バケット閾値: high>=0.66, mid>=0.33, それ未満 low、突合0件は none
```

CVSS は **v3/v4 の max**（最悪ケース駆動。GitHub API は v4 ベクタ未保有でも score=0 を返すため、欠損を 0 とみなし高い方を採る）。

EPSS が取得できない場合（CVE 未割当・FIRST 未収載・取得失敗）は、EPSS 項を落とし **存在する重みで再正規化**する（`score(v) = (cvss/10)·scope`、w_cvss を実効 1.0 へ）。「不明」を「リスク 0」とみなす下方バイアスを避け、CVSS 単独でも本来のレンジを使う。`w_cvss=0` かつ EPSS 不明の縮退は 0 除算回避でスコア 0。

## 突合（F2 / M2 の肝） — 強度「緩」

```
reconcile(prDeps, openAlerts):          # prDeps: fetch-metadata 由来 (name, ecosystem, newVersion)
  resolved = []
  for dep in prDeps:
    key = (dep.ecosystem, normalize(dep.name))
    for a in openAlerts where (a.ecosystem, normalize(a.package)) == key:
      resolved.push(toVuln(a, dep))     # 「緩」: バージョン比較せず ecosystem+name 一致 + open のみ
  return dedupeByGhsaId(resolved)
```

**なぜ緩か**: 厳密なバージョン比較はエコシステムごとに文法・順序規則・範囲記法が異なり
（npm=SemVer / pip=PEP440 / Maven=独自区間 等）、全対応はブリーフ非ゴールの「エコシステム個別ロジック」になる。
Dependabot のセキュリティ PR は定義上 open alert を修正するために起票されるため、
ecosystem+name 一致 + open で「この PR が解決する脆弱性」とみなして実用上十分。
将来 `node-semver` で SemVer 系のみ厳密化する「中」へ格上げ可能（M3 候補）。

## コメント表示（F6）の確度方針

- 緩突合では「CVE 一覧自体」は GitHub alert DB 由来の実在データで正確。
  不確かなのは「この PR が解決するか」の一点のみ。
- よってコメントは **「解決する脆弱性」と断定せず「対象パッケージの open alert」枠**で表示し、
  各行に確度マーク、脚注で突合方法（ecosystem+name 一致・バージョン未検証）を開示する。
- **M1（単一依存）**: fetch-metadata の alert-lookup は GitHub が依存に紐付けた ghsa-id/cvss を直接返す
  高確度データ。CVE をそのまま表示してよい。
- **M2（グループPR）**: 緩突合の確度マークが効く。「緩・正直表記」で開始し、M3 で「中」へ格上げ可。

## ラベル（F5）

- バケット → `label-high` / `label-mid` / `label-low` のいずれか 1 つを付与。
- 管理ラベル群 = **`label-high/mid/low` の 3 値固定**。該当しない管理ラベルは外し、該当 1 つを付ける。
  他人が付けたラベルには触らない。
- 注意: 実行間でラベル名 input を変更すると旧ラベルが孤児化しうる（README で注意喚起）。
- ラベルは存在しなければ色付きで作成。

## コメント upsert（F6）

- 先頭マーカー `<!-- dependabot-triage -->` で既存コメントを検索し、あれば update / なければ create。
- `synchronize` 再実行でコメントが増殖しないことを回帰テストで固定。

## 非機能 / セキュリティ

- **PR をブロックしない**: トリアージ失敗（API エラー等）は warning に留める。
  `setFailed` は設定不備（PAT 欠如等）に限定。`fail-on-error` input で切替。
- 最小権限: PAT は Dependabot alerts = Read-only。workflow `permissions` は
  `pull-requests: write` + `contents: read`。
- レート制限・一時失敗に指数バックオフ・リトライ（上限付き）。
- ログは `core.info`/`core.debug` で段階化、秘密情報を出さない。

## fetch-metadata 配線 = 案 A（inputs パススルー）

workflow が `dependabot/fetch-metadata` を先に実行し、その出力をこの Action の `with:` に配線する。
将来 UX 改善として composite 薄ラッパ（案 B）を「追加の入口」として被せられる。コア JS は不変。

## action.yml inputs/outputs

inputs:
- 認証: `github-token`（必須・PAT）
- fetch-metadata パススルー: `dependency-names`, `dependency-type`, `package-ecosystem`,
  `previous-version`, `new-version`, `dependency-group`, `alert-ghsa-id`, `alert-cvss`
- 重み/係数: `weight-cvss`(0.6), `weight-epss`(0.4), `scope-prod`(1.0), `scope-dev`(0.4), `scope-indirect`(0.7)
- 閾値/ラベル: `threshold-high`(0.66), `threshold-mid`(0.33), `label-high`(triage:fix-now),
  `label-mid`(triage:review), `label-low`(triage:low-here)
- トグル: `aggregate`(max|sum, 既定 max), `comment`(true), `label`(true), `fail-on-error`(false)

outputs: `score`, `bucket`(high|mid|low|none), `vulnerabilities`(JSON)

## マイルストーン

- **M1**: 単一依存。fetch-metadata 出力のみで score→ラベル＋コメント upsert。設定は既定値固定。
- **M2**: グループPR対応（ハイブリッド突合・複数脆弱性集約・コメント列挙）。
- **M3**: inputs 設定可能化・outputs 公開・README・突合「中」格上げ検討。
- **M4**: リリース整備（`v1` 移動タグ・CI ビルド差分検出・自身を Dependabot dogfooding）。

## M1 タスク分解（テスト→実装、1 PR 1 関心）

| PR | 関心 | 所有ファイル |
|---|---|---|
| A | プロジェクト雛形 | `package.json` / `tsconfig.json` / `vitest.config.ts` / lint / `action.yml`(枠) / `.github/workflows/ci.yml` |
| B | 型 + config | `types.ts` / `config.ts` |
| C | スコア（純粋） | `score.ts` |
| D | コメント本文生成（純粋） | `comment.ts`(render) |
| E | github アダプタ + ラベル付替え | `github.ts` / `labels.ts` |
| F | コメント upsert | `comment.ts`(upsert) |
| G | オーケストレーション統合 + ncc build + dist | `run.ts` / `main.ts` / `dist/` |
