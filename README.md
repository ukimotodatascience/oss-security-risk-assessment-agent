# OSSリスク診断エージェント 診断仕様書

本エージェントは、GitHubリポジトリを対象に、  
OSS導入・利用時に発生し得るセキュリティリスクを構造的に診断する。

対象範囲：
- Python / Node.js プロジェクト
- Dockerfile
- GitHub Actions
- ライセンス情報
- リポジトリのガバナンス情報

診断はすべて明示的なルールベースで行い、  
各検出には必ず根拠（該当ファイル・該当箇所）を付与する。

---

# 診断カテゴリA：依存関係の脆弱性リスク

## A-1. 既知の脆弱性を含む依存ライブラリ

### ■ リスク概要
既知のCVEが存在するライブラリを利用している場合、
リモートコード実行、情報漏洩、権限昇格などの重大な攻撃が可能となる。

### ■ 判定インプット
- requirements.txt
- poetry.lock
- package.json
- package-lock.json
- OSV.dev / GitHub Advisory Database

### ■ 判定条件
依存ライブラリの名称およびバージョンが、
脆弱性データベースに登録されている脆弱バージョン範囲に該当する場合、
リスクとして検出する。

重大度は以下を基準に決定する：
- CVSSスコア
- KEV登録状況（実際に悪用されているか）

---

## A-2. 依存バージョン未固定

### ■ リスク概要
依存バージョンが固定されていない場合、
ビルドごとに異なるコードが取得され、
サプライチェーン攻撃や再現性欠如の原因となる。

### ■ 判定インプット
- requirements.txt
- package.json
- lockファイルの有無

### ■ 判定条件
依存バージョン指定にワイルドカードや範囲指定のみが含まれ、
かつロックファイルが存在しない場合、リスクとして検出する。

---

# 診断カテゴリB：サプライチェーンリスク

## B-1. GitHub Actionsのバージョン未固定

### ■ リスク概要
外部アクションをタグ参照のみで利用している場合、
タグ改ざんにより任意コード実行が可能となる。

### ■ 判定インプット
- .github/workflows/*.yml

### ■ 判定条件
uses: で指定されたアクションがコミットSHAではなく、
タグ参照のみで指定されている場合、リスクとして検出する。

---

## B-2. Dockerベースイメージがlatest指定

### ■ リスク概要
latestタグは可変であり、
予期せぬ脆弱性や不正コードが混入する可能性がある。

### ■ 判定インプット
- Dockerfile

### ■ 判定条件
FROM命令でタグがlatest指定、
またはタグが明示されていない場合、リスクとして検出する。

---

## B-3. curl | bash 等の直接実行

### ■ リスク概要
外部から取得したスクリプトを検証せずに直接実行すると、
改ざんやMITM攻撃の影響を受ける。

### ■ 判定インプット
- Dockerfile
- CIスクリプト
- シェルスクリプト

### ■ 判定条件
curl または wget の出力をパイプで bash / sh に直接渡している場合、
重大リスクとして検出する。

---

# 診断カテゴリC：設定・利用上のリスク

## C-1. コンテナがrootで実行される

### ■ リスク概要
root実行は侵害時の被害拡大につながる。

### ■ 判定インプット
- Dockerfile

### ■ 判定条件
USER命令が存在しない場合、
root実行の可能性があるとして検出する。

---

## C-2. 機密情報ファイルの含有

### ■ リスク概要
.env や秘密鍵ファイルがリポジトリに含まれると、
永続的な情報漏洩につながる。

### ■ 判定インプット
- リポジトリ内ファイル一覧

### ■ 判定条件
.env、.pem、.key 等の機密性が高いファイルが
.gitignore対象外として存在する場合、重大リスクとして検出する。

---

## C-3. アプリが0.0.0.0で待ち受け

### ■ リスク概要
無防備な外部公開の可能性がある。

### ■ 判定インプット
- アプリ設定ファイル
- Dockerfile

### ■ 判定条件
明示的に0.0.0.0でバインドしており、
リバースプロキシ等の制御構成が確認できない場合、
リスクとして検出する。

---

# 診断カテゴリD：ガバナンス・継続性リスク

## D-1. 更新停止

### ■ リスク概要
長期間更新がないOSSは、
新たな脆弱性に対応されない可能性がある。

### ■ 判定インプット
- GitHub API（最終コミット日時）

### ■ 判定条件
最終コミットが12ヶ月以上前である場合、
保守停止リスクとして検出する。

---

## D-2. Bus Factor 1

### ■ リスク概要
主要なコミットの大半を単一開発者が担っている場合、
継続性が低い。

### ■ 判定インプット
- GitHub contributors API

### ■ 判定条件
特定の開発者が総コミット数の80%以上を占める場合、
依存リスクとして検出する。

---

# 診断カテゴリE：ライセンスリスク

## E-1. GPL系ライセンス

### ■ リスク概要
商用利用時にソースコード公開義務が発生する可能性がある。

### ■ 判定インプット
- LICENSEファイル

### ■ 判定条件
GPL-2.0、GPL-3.0、AGPL等の強いコピーレフトライセンスが検出された場合、
商用利用前提の場合にリスクとして検出する。

---

## E-2. ライセンス未定義

### ■ リスク概要
法的利用条件が不明であり、
利用自体がリスクとなる。

### ■ 判定インプット
- LICENSEファイル有無

### ■ 判定条件
LICENSEファイルが存在しない場合、
法的リスクとして検出する。

---

# 診断カテゴリF：CI/CD機密情報リスク

## F-1. secretsのログ出力

### ■ リスク概要
CIログに機密情報が出力されると、
第三者に取得される可能性がある。

### ■ 判定インプット
- workflowファイル

### ■ 判定条件
secrets変数をecho等で標準出力している場合、
重大リスクとして検出する。

---

# 診断の基本原則

1. すべての検出は明示的なルールに基づく。
2. 各リスクは証拠（該当ファイル・行）を伴う。
3. リスクは影響度と悪用可能性に基づき重大度分類される。
4. ルールは拡張可能な構造で定義される。
5. LLMは説明生成用途に限定し、判定ロジックには使用しない。

---

# スコアリング仕様（Risk / Maturity）

本ツールは検出結果 `risks` から、以下2つの指標を算出します。

- **Risk Score (0-100)**: 高いほど危険
- **Maturity Score (0-100)**: 高いほど成熟（`100 - Risk Score`）

## Severity数値化

- LOW = 1
- MEDIUM = 3
- HIGH = 6
- CRITICAL = 10

## カテゴリ重み（A-F）

- A: 0.30
- B: 0.20
- C: 0.20
- D: 0.15
- E: 0.10
- F: 0.05

## 計算概要

1. カテゴリごとに Severity の平均値を取り、0-100へ正規化
2. 上記カテゴリスコアに重みを適用して合算
3. `Risk Score` を得る
4. `Maturity Score = 100 - Risk Score`

JSON出力では `summary` に以下が追加されます。

- `risk_score`, `maturity_score`
- `category_scores`
- `counts_by_severity`, `counts_by_category`
- `total_risks`, `critical_count`
- `unscored_categories`（重み未定義カテゴリ）

---

# 実装済みの品質改善（2026-03）

## 1) テスト整合性の改善
- ルール実装名とテスト参照名の不一致を修正（C/E/Fカテゴリ）。
- `pyproject.toml` に `pytest-cov` とカバレッジゲートを追加。
  - `--cov=oss_risk_agent`
  - `--cov-fail-under=80`

## 2) 例外処理の可視化
- `Scanner` に `warnings` を追加し、
  ルールロード失敗・初期化失敗・実行失敗を `ScanWarning` として保持。
- CLIのJSON出力を以下構造に拡張。
  - `risks`: 検出結果
  - `warnings`: 診断中の警告（失敗したルール等）

## 3) 誤検知低減（B-3/C-4）
- B-3（direct execution）で重複ファイル解析を排除。
- B-3で過剰な `except` 握りつぶしを減らし、対象例外を限定。
- C-4（高エントロピー秘密）で以下の誤検知抑制を導入。
  - しきい値強化（長さ24以上、エントロピー4.8以上）
  - プレースホルダー値（example/dummy等）の除外
  - スキャン対象をコード・設定ファイル中心に限定

## 4) 実行例
```bash
oss-risk-agent scan . --format json --output-file result.json
```

`result.json` には、検出されたリスクに加えて、スキャン時の警告も含まれます。

CIゲートとして以下も利用できます。

```bash
oss-risk-agent scan . --format text --max-risk-score 70 --fail-on-critical
```

- `--max-risk-score`: 指定閾値を超えたら終了コード1
- `--fail-on-critical`: CRITICAL検出時に終了コード1

---

# OPA / Rego 連携仕様（G-1）

`oss_risk_agent/core/opa_integration.py` の `G1OpaPolicyRule` は、
リポジトリ直下に `policies/` ディレクトリが存在する場合に有効化されます。

現状の入力対象は `package.json` です。内部的には以下の式で評価します。

- `data.oss_risk.package_json`

## 実行インターフェース

`OPAIntegrationEngine.evaluate(input_data, policy_name)` は以下の流れで動作します。

1. `input_data` を一時JSONファイルへ保存
2. `opa eval -f json -d <policies_dir> -i <tmp.json> data.<policy_name>` を実行
3. OPA出力を `RiskRecord` へ変換

`opa` バイナリが未インストール、または実行失敗/JSONパース失敗時は
空配列を返します（スキャン自体は継続）。

## Rego側の推奨出力スキーマ

`expressions[].value` は以下形式を推奨します。

```json
{
  "deny": [
    {
      "msg": "危険な依存バージョンです",
      "severity": "CRITICAL",
      "file": "package.json",
      "line": 12,
      "evidence": "left-pad@*"
    }
  ],
  "warn": [
    {
      "msg": "推奨設定が不足しています",
      "severity": "MEDIUM",
      "file": "package.json"
    }
  ]
}
```

## `RiskRecord` へのマッピング

- `category`: 固定で `"G-1"`
- `name`: `name` があれば利用、なければ `OPA Policy Violation (<policy_name>)`
- `severity`: `severity` を `LOW/MEDIUM/HIGH/CRITICAL` として解釈
  - `deny` の既定値: `HIGH`
  - `warn` の既定値: `MEDIUM`
- `description`: `msg` / `message` / `description` の順で採用
- `target_file`: `target_file` / `file` / `path` の順で採用
- `line_number`: `line_number` / `line`
- `evidence`: `evidence` がなければ違反オブジェクトをJSON文字列化
