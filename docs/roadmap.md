# 実装ロードマップ

全 PR の見取り図。各 PR Issue は着手直前に `create-issue` で born-Ready 起票し、対応する GitHub Milestone に紐付ける。
設計の根拠は [design.md](./design.md) を参照。

進捗記号: ✅ 完了 / 🔼 進行中 / ⬜ 未着手

## M1 — MVP（単一依存・fetch-metadata のみ・既定値固定）

| PR | 関心 | 所有ファイル | 依存 | 状態 |
|---|---|---|---|---|
| A | プロジェクト雛形 | package.json / tsconfig / vitest / lint / action.yml枠 / ci.yml | — | ✅ #1 |
| B | 共有型・設定パース | types.ts / config.ts | — | ✅ #4 |
| C | スコア計算（純粋） | score.ts | B | ✅ #6 |
| D | コメント本文生成（純粋） | comment.ts(render) + types(epssAvailable) | C | ⬜ |
| E | github アダプタ | github.ts（octokit ラッパ: コメント/ラベル CRUD） | — | ⬜ |
| F | ラベル付替え | labels.ts | E | ⬜ |
| G | コメント upsert | comment.ts(upsert) | E, D | ⬜ |
| H | メタデータ（M1） | metadata.ts（fetch-metadata パススルー→単一 Vulnerability） | B | ⬜ |
| I | オーケストレーション統合 | run.ts / main.ts(guard) / outputs / dist 配線 | 全部 | ⬜ |

M1 完了で単一依存の Dependabot PR に対し score→ラベル＋コメント upsert が E2E で動く。

## M2 — グループPR対応（緩突合・複数脆弱性・EPSS）

| PR | 関心 | 所有ファイル | 状態 |
|---|---|---|---|
| EPSS-1 | EPSS 取得アダプタ | epss.ts（GHSA→CVE→FIRST API・並列・メモ化・失敗時0・epssAvailable）＋run配線 | ⬜ |
| M2-1 | alerts 取得 | github.ts 拡張（GET /dependabot/alerts ページング） | ⬜ |
| M2-2 | 突合（緩） | metadata.ts 拡張（ecosystem+name 一致・複数 Vulnerability） | ⬜ |
| M2-3 | コメント拡張 | comment.ts 拡張（確度マーク・open alert 枠・複数行・グループ表示） | ⬜ |
| M2-4 | run 配線 | グループ経路（集約は score 済） | ⬜ |

> EPSS は M1 では未取得（fetch-metadata に無く score は epss=0）。M2 の入口で実取得を追加する。

## M3 — 設定可能化・outputs・README・突合中

| PR | 関心 | 状態 |
|---|---|---|
| M3-1 | README（使い方・workflow 例・inputs/outputs 表・PAT/権限） | ⬜ |
| M3-2 | 数値範囲バリデーション（PR-B 改善提案の回収） | ⬜ |
| M3-3 | 突合「中」格上げ（node-semver で npm 厳密化）※任意 | ⬜ |

## M4 — リリース整備

| PR | 関心 | 状態 |
|---|---|---|
| M4-1 | release.yml（タグ＋v1 移動タグ） | ⬜ |
| M4-2 | dependabot.yml（dogfooding。version updates 設定） | ⬜ |
| M4-3 | Marketplace 公開準備（README 必須項目・public 化判断） | ⬜ |

## 粒度メモ

E+F の統合、H を I に畳む等は着手時の判断で前後しうる。1 PR 1 関心を維持する範囲で調整する。
