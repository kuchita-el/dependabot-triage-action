# リリース／配布モデル

本 Action の配布は **immutable releases（不変リリース）** を採用する（#48）。consumer が参照する版の不変性（一度参照した版の中身が後から変わらないこと）を producer 側で強制する。

## 配布モデル選定（#48）

リリースモデルとして 2 案を比較し、**案 (a) Immutable Releases/Tags を採用**した。

- **(a) Immutable Releases/Tags（採用）** — GitHub の不変リリース（2025 Q4 GA）を有効化し、release 固有タグ `vX.Y.Z` を Release 発行時に commit へ固定（不変化）する。consumer は `@vX.Y.Z` 固定参照＋Dependabot で更新する。producer 側で「バージョン = 不変アーティファクト」を強制でき、公開済みタグの force-update は GitHub に拒否される。ゴール（参照版の不変性担保）に一致する。
- **(b) floating v1 維持＋SHA ピン併用（却下）** — タグ自体は可変のままで、不変性が consumer の SHA ピン留め規律に依存する。producer はバージョン不変性を保証できず、タグ参照した consumer は保護されない。GA 済みで (a) の採用リスクが無く、段階移行（b→a）は捨て工数となるため不採用。

### タグの併存方針

floating `v1` は廃止せず **併存** する。GitHub Release に紐づかない単なる git タグは可動のまま残るため、両者は共存できる。

| タグ | 種別 | 用途 |
|---|---|---|
| `vX.Y.Z` | immutable（Release 紐づき・固定） | consumer の不変参照用。推奨参照先 |
| `v1` | movable（Release 紐づかない git タグ） | 利便用の version tag。最新の互換 commit を指すよう人手で移動 |

## Immutable Releases の有効化

一度だけ行うリポジトリ設定。**有効化後に発行する Release のみ不変化される**（既存 Release は遡及しない）。

- **リポジトリ単位**: Settings → 「Releases」セクション → **Enable release immutability** にチェック。
- **Org 単位**（任意）: Organization Settings → Code, planning, and automation → Repository → General → 「Releases」セクション → ドロップダウンで All / Selected repositories を選択。

不変化されると、Release に紐づく git タグは特定 commit に固定され、Release が存在する間は変更・削除できない。アセットも改変・削除から保護され、暗号的な release attestation が自動生成される。

## リリースフロー

`release.yml` を **`workflow_dispatch`（version 入力）** で手動起動する。タグ push をトリガにする旧方式（公開済みタグを `git push -f` で付け替え）は廃止した。

1. Actions UI で「Release (immutable vX.Y.Z)」を選択し、`version`（`vX.Y.Z` 形式）を入力して起動する。起動 ref は既定 main。
2. workflow が実行する:
   1. version 形式を検証し、既存タグへの再リリースを早期に弾く（immutable は再付与不可）。
   2. 起動 ref から `npm ci && npm run build` で dist を決定的に生成する。
   3. dist を焼き込んだ commit を作る（`dist/` は VCS 管理外のため `-f` で強制ステージング。commit は main へ戻さずタグ経由でのみ到達可能）。
   4. その commit に `vX.Y.Z` タグを **新規** 作成して push する（force-update しない）。
   5. `gh release create` で GitHub Release を発行する → 有効化済みならタグが commit に固定（不変化）。
3. （任意・人手）floating `v1` を焼込み済み commit へ移動する。

> dist はタグの commit に含めるため、Release アセットは添付しない。「draft 作成 → アセット添付 → publish」の推奨フローはバイナリ等のアセットを伴う場合の手順であり、本 Action では不要。

### 発行失敗時の復旧（孤児タグ）

ステップ 4（タグ push）と 5（Release 発行）は非原子的のため、4 成功・5 失敗（API 一時エラー、有効化直後の不整合等）でタグだけ残ることがある。この場合タグは Release 未紐づけ＝**不変化されていない**ため削除でき、ステップ 1 の既存タグ検出で再実行がブロックされる。**孤児タグを削除してから再実行**する:

```bash
git push origin :refs/tags/vX.Y.Z   # Release 未発行なら削除可
# → release.yml を同 version で再実行
```

初回リリース（immutability 有効化直後）が最も発生しやすい局面のため留意する。

## 不変性の検証手順（AC1）

有効化が効いていること（公開済みタグの force-update が拒否されること）を確認する。リリース発行済みの `vX.Y.Z` に対し以下を実行する。

```bash
# 別 commit へタグを付け替えて force-push を試行する（拒否されるはずの操作）
git tag -f vX.Y.Z <別の commit>
git push -f origin refs/tags/vX.Y.Z
```

Immutable Releases 有効時、この `git push -f` は GitHub により **拒否**される。拒否時のエラー出力（`! [remote rejected]` 等）を本ドキュメントに追記し、不変性が機構として効いていることの記録とする。

初回 immutable リリース `v1.2.0`（Release 発行済み）に対し別 commit への付替え force-push を試行した実ログ（2026-06-18）:

```
remote: error: GH013: Repository rule violations found for refs/tags/v1.2.0.
remote: Review all repository rules at https://github.com/kuchita-el/dependabot-triage-action/rules?ref=refs%2Ftags%2Fv1.2.0
remote:
remote: - Cannot update this protected ref.
remote:
To github.com:kuchita-el/dependabot-triage-action.git
 ! [remote rejected] v1.2.0 -> v1.2.0 (push declined due to repository rule violations)
error: failed to push some refs to 'github.com:kuchita-el/dependabot-triage-action.git'
```

remote の `v1.2.0` は元 commit を指したまま不変。Release 発行により当該タグが protected ref 化され、force-update が機構として拒否されることを確認した。

## 参考

- [Immutable releases — GitHub Docs](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)
- [Preventing changes to your releases — GitHub Docs](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/preventing-changes-to-your-releases)
- [Using immutable releases and tags to manage your action's releases — GitHub Docs](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/using-immutable-releases-and-tags-to-manage-your-actions-releases)
- [Immutable Releases [GA] (github/roadmap#1138)](https://github.com/github/roadmap/issues/1138), [Immutable Actions [GA] (github/roadmap#592)](https://github.com/github/roadmap/issues/592)
