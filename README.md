# Dependabot Vulnerability Triage Action

Dependabot PR の脆弱性を **このリポジトリ基準の深刻度** へ畳み込み、ラベル 1 つの付与と単一コメントの upsert を行う GitHub Action。

- CVSS と EPSS を重み付けし、依存スコープ（production / development / indirect）で補正したスコアを算出
- スコアを `high` / `mid` / `low` バケットへ分類し、対応するトリアージラベルを 1 つ付与
- PR に脆弱性サマリのコメントを upsert（再実行で増殖しない）
- `pull_request_target` で動作し、PR のコードは checkout / 実行しない（インジェクション対策）

## 仕組み

`dependabot/fetch-metadata` を先に実行し、その出力をこの Action の `with:` に配線する（パススルー方式）。Action は fetch-metadata の依存情報と、リポジトリの open な Dependabot alerts をパッケージ名で突合し、スコア → ラベル → コメントを実行する。

```
fetch-metadata → triage action
  ├─ 設定パース（PAT 必須チェック）
  ├─ ガード: actor == dependabot[bot] か（否なら no-op 正常終了）
  ├─ open alerts 取得 + パッケージ名で突合
  ├─ EPSS 取得（GHSA→CVE→FIRST API、失敗時 0）
  ├─ スコア算出 → 集約 → バケット判定
  ├─ ラベル付替え（label 有効時）
  ├─ コメント upsert（comment 有効時）
  └─ outputs（score / bucket / vulnerabilities）
```

## 必要な権限とトークン

> [!IMPORTANT]
> **既定の `GITHUB_TOKEN` では Dependabot alerts を読めない。** 専用の PAT または GitHub App トークンが必須。

- **PAT（または App トークン）**: Dependabot alerts の **Read** 権限が必要。`github-token` および `fetch-metadata`（`alert-lookup: true` 時）に渡す。Secret（例: `DEPENDABOT_TRIAGE_PAT`）に格納する。
- **workflow `permissions`**: コメント / ラベルの書込みは PAT(octokit) が担うため、ジョブ既定トークンは最小権限でよい（`contents: read`）。

## 使い方

`.github/workflows/triage.yml`:

```yaml
name: Dependabot Triage

on:
  pull_request_target:
    types: [opened, synchronize, reopened]

# 同一 PR の run を直列化し、古い run はキャンセル（コメント二重作成・ラベル競合を防ぐ）
concurrency:
  group: triage-${{ github.event.pull_request.number }}
  cancel-in-progress: true

permissions:
  contents: read

jobs:
  triage:
    runs-on: ubuntu-latest
    # Dependabot 以外の PR は対象外
    if: ${{ github.event.pull_request.user.login == 'dependabot[bot]' }}
    steps:
      - name: Fetch Dependabot metadata
        id: meta
        uses: dependabot/fetch-metadata@v2
        with:
          github-token: ${{ secrets.DEPENDABOT_TRIAGE_PAT }}

      - name: Triage
        id: triage
        # 不変な固定バージョンを参照する（推奨）。更新は Dependabot に任せる（下記「配布とバージョン参照」）
        uses: kuchita-el/dependabot-triage-action@v1.0.0
        with:
          github-token: ${{ secrets.DEPENDABOT_TRIAGE_PAT }}
          dependency-names: ${{ steps.meta.outputs.dependency-names }}
          dependency-type: ${{ steps.meta.outputs.dependency-type }}
          package-ecosystem: ${{ steps.meta.outputs.package-ecosystem }}
          previous-version: ${{ steps.meta.outputs.previous-version }}
          new-version: ${{ steps.meta.outputs.new-version }}
          dependency-group: ${{ steps.meta.outputs.dependency-group }}
```

## 配布とバージョン参照

本 Action は **immutable releases（不変リリース）** で配布する。`vX.Y.Z` は Release 発行時に commit へ固定（不変化）され、一度参照した版の中身は後から変わらない。consumer は**固定バージョン参照**を推奨する。

```yaml
# 不変な固定バージョン参照（推奨）
uses: kuchita-el/dependabot-triage-action@v1.0.0
```

更新は Dependabot に任せる。consumer 側の `.github/dependabot.yml` に `github-actions` エコシステムを設定すると、新バージョン公開時に参照を更新する PR が自動で立つ。

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

> [!NOTE]
> floating `v1`（最新の互換版を指す可動タグ）も併存するが、不変性は担保されない。再現性のため固定参照を推奨する。配布モデルの詳細は [docs/release.md](docs/release.md)。

## inputs

### 認証

| 名前 | 必須 | 既定値 | 説明 |
|------|------|--------|------|
| `github-token` | ✅ | — | Dependabot alerts を読取可能な PAT または App トークン |

### fetch-metadata パススルー

`dependabot/fetch-metadata` の出力を配線する。いずれも任意（既定は空）。

| 名前 | 既定値 | 説明 |
|------|--------|------|
| `dependency-names` | `''` | 更新依存名（カンマ区切り・全件） |
| `dependency-type` | `''` | `direct:production` / `direct:development` / `indirect` |
| `package-ecosystem` | `''` | `npm`, `pip`, ... |
| `previous-version` | `''` | 更新前バージョン |
| `new-version` | `''` | 更新後バージョン |
| `dependency-group` | `''` | グループ PR 名（非グループは空） |

### スコア重み・スコープ係数

`score(v) = (weight-cvss · cvss/10 + weight-epss · epss) · scope(depType)`

| 名前 | 既定値 | 説明 |
|------|--------|------|
| `weight-cvss` | `0.6` | スコア式の CVSS 重み |
| `weight-epss` | `0.4` | スコア式の EPSS 重み |
| `scope-prod` | `1.0` | `direct:production` のスコープ係数 |
| `scope-dev` | `0.4` | `direct:development` のスコープ係数 |
| `scope-indirect` | `0.7` | `indirect` のスコープ係数 |

### バケット閾値・ラベル名

| 名前 | 既定値 | 説明 |
|------|--------|------|
| `threshold-high` | `0.66` | これ以上のスコアで `high` バケット |
| `threshold-mid` | `0.33` | これ以上のスコアで `mid` バケット |
| `label-high` | `triage:fix-now` | `high` バケットに付与するラベル名 |
| `label-mid` | `triage:review` | `mid` バケットに付与するラベル名 |
| `label-low` | `triage:low-here` | `low` バケットに付与するラベル名 |

> [!NOTE]
> 管理ラベルは `label-high` / `label-mid` / `label-low` の 3 値固定。該当 1 つを付け、他の管理ラベルは外す（他人が付けたラベルには触らない）。実行間でラベル名を変更すると旧ラベルが孤児化しうる。

### 集約・挙動トグル

| 名前 | 既定値 | 説明 |
|------|--------|------|
| `aggregate` | `max` | PR 全体スコアの集約方式（`max` / `sum`） |
| `comment` | `true` | コメント upsert を有効にするか |
| `label` | `true` | ラベル付与を有効にするか |
| `fail-on-error` | `false` | トリアージ失敗（API エラー等）時に `setFailed` するか |

## outputs

| 名前 | 説明 |
|------|------|
| `score` | PR 全体スコア（0..1） |
| `bucket` | バケット（`high` / `mid` / `low` / `none`） |
| `vulnerabilities` | 脆弱性詳細の JSON 配列 |

## 突合とコメントの確度

open alerts と PR の更新依存は **パッケージ名一致のみ** で突合する（バージョン未検証）。このため、コメントは「この PR が解決する脆弱性」と断定せず、**「対象パッケージの open alert（解決は未検証）」** 枠で表示する。CVE 一覧自体は GitHub alert DB 由来の実在データで正確。

## ライセンス

MIT
