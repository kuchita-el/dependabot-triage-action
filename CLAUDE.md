# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 概要

Dependabot PR の脆弱性を「このリポジトリ基準の深刻度」へ畳み込む GitHub Action（TypeScript / Node 24）。CVSS と EPSS を重み付けし依存スコープで補正したスコアを算出 → `high`/`mid`/`low` バケットへ分類 → トリアージラベル 1 つ付与 + PR コメントを upsert。詳細仕様は `docs/design.md`（設計合意）と `docs/roadmap.md`（M1〜M4 の分解）。

## コマンド

Node/npm は **mise 経由**（`mise.toml` で Node 24 固定）。PATH に直接無い場合は mise 経由で呼ぶ。

```bash
npm run typecheck      # tsc --noEmit（src と tsconfig.test.json の両方）
npm run lint           # eslint .
npm run format:check   # prettier --check .（CI が強制。push 前に必須）
npm run format         # prettier --write .（整形を適用）
npm test               # vitest run
npm run test:watch     # vitest watch
npm run build          # ncc build src/main.ts -o dist（dist/index.js を生成）

# 単一テストファイル / 単一ケース
npx vitest run tests/score.test.ts
npx vitest run -t "ケース名の部分一致"
```

CI（`.github/workflows/ci.yml`）は typecheck → lint → format:check → test → build → **dist/ の差分チェック** を順に実行。`src/` を変更したら必ず `npm run build` して `dist/` をコミットすること（ビルド成果物 `dist/index.js` をリポジトリにコミットする運用。差分があると CI が落ちる）。

## アーキテクチャ

**DI による合成ルート分離**が中核。`src/main.ts` だけが実 `@actions/core` / `@actions/github` / HTTP に触れ、それらを `run()` の依存（`RunDeps`）として注入する。`main.ts` はロジックを持たず vitest coverage から除外（`vitest.config.ts`）。ロジックはすべて `run.ts` 以下の純粋・テスト可能な層にある。

データフロー（`src/run.ts` の `run()` がオーケストレーション）:

```
ガード(actor==dependabot[bot]か) → parseConfig
  → listOpenDependabotAlerts → reconcileVulnerabilities（名前一致で突合）
  → enrichWithEpss（GHSA→CVE→EPSS）→ evaluate（スコア→バケット）
  → setOutput（副作用より先）→ applyBucketLabel → upsertComment
```

層ごとの責務:

- `config.ts` — `parseConfig`。action.yml inputs を検証付きで `Config` へ。`DEFAULTS` は既定値の単一ソースで **action.yml の default とミラー必須**。不正値は `ConfigError`（`run()` で常に `setFailed`）。
- `metadata.ts` — `reconcileVulnerabilities`。open alerts と PR 更新依存を**パッケージ名一致のみ**で突合（ecosystem は突合キーにしない）。`classifyConfidence` で new-version が修正版以上なら確度を `version`（中）へ格上げ。
- `epss.ts` — `enrichWithEpss`。GHSA→advisory（CVE 群＋GitHub 同梱 EPSS）をメモ化。EPSS は **GitHub `epss.percentage`（advisory 単位 1 値）を優先**し、無い場合のみ FIRST を複数 CVE の max で補完する。取得失敗は当該 vuln のみ `epss=0` にフォールバックし全体は止めない。
- `score.ts` — `score = (w_cvss·cvss/10 + w_epss·epss)·scope` を集約（max/sum）し [0,1] クランプ → バケット。非有限値は silent に落とさず throw。EPSS 不明（`epssAvailable=false`）時は EPSS 項を落とし存在重みで再正規化（不明を 0 とみなさない）。
- `github.ts` — `createGithubClient`。octokit を隠蔽するアダプタ。ドメイン層は octokit を直接触らず本クライアント経由。
- `labels.ts` — `applyBucketLabel`。管理ラベル 3 値のうち 1 つだけ付与、他は外す（他人のラベルには触らない）。付与を除去より先に行い、途中失敗時に無ラベルでなく over-labeled で終わらせる。
- `comment.ts` — `renderComment`（純粋）+ `upsertComment`。`MARKER` 行頭一致でコメントを単一に保つ（再実行で増殖させない）。
- `types.ts` — 共有型の単一ソース。

## 設計上の不変条件・注意点

- **silent failure を避ける設計**が一貫したテーマ。エラーは握り潰さず warning/throw で顕在化させる。コード変更時はこの方針を壊さないこと。
- `fail-on-error`（既定 false）はトリアージ失敗（API/EPSS エラー）時に PR をブロックするかの切替。設定不備（`ConfigError`）はこれに依らず常に `setFailed`。
- 突合はバージョン未検証の「名前一致」が前提。コメントは「解決する」と断定せず「対象パッケージの open alert（未検証）」枠で表示する。
- `action.yml` の inputs を増減したら `config.ts` の `parseConfig`/`DEFAULTS` と README の表を同期する。
- `pull_request_target` で動作し PR コードは checkout/実行しない（インジェクション対策）。

## コードスタイル

prettier（`singleQuote`, `semi`, `printWidth: 100`, `trailingComma: all`）。tsconfig は strict 全部入り（`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` 等）。コメント・命名は日本語で簡潔に書かれており、既存の密度・トーンに合わせる。
