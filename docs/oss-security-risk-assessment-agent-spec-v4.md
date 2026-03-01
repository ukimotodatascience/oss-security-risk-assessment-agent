# OSS Security Risk Assessment Agent
## 仕様書 v4（実務導入・監査完全対応版）

---

# 1. 目的

本エージェントは、GitHubリポジトリを対象にOSS導入・利用に伴うセキュリティリスクを構造的・再現可能・監査可能な形で診断する。

本仕様は以下を満たす：

- DevSecOps統合
- 監査証跡提出可能
- 誤検知抑制設計
- リスク受容管理
- SLA追跡
- 複合リスク評価
- 定量スコアリング
- エンタープライズ運用耐性

---

# 2. 想定脅威モデル

## 2.1 想定攻撃者

| 区分 | 想定能力 |
|------|----------|
| Opportunistic attacker | 公開PoC利用 |
| 金銭目的攻撃者 | RCE / データ窃取 |
| サプライチェーン攻撃者 | CI/CD侵害 |
| 内部不正者 | 権限悪用 |

## 2.2 防御対象

- 本番環境データ
- CI/CDパイプライン
- ソースコード
- APIキー等機密情報

---

# 3. 設計原則

1. 判定は完全ルールベース
2. すべての検出に証拠付与
3. 判定ロジック明文化
4. LLMは説明生成のみ利用
5. suppressは期限付き
6. 差分検出標準実装
7. リスク受容はログ保存
8. パラメータは外部設定可能
9. 値を捏造しない（取得不可はN/A明示）

---

# 4. 実行モード

- PRモード（差分のみ）
- Nightlyフルスキャン
- 監査モード（履歴解析）
- SBOM生成専用モード

---

# 5. リスクスコアリングモデル

## 5.1 スコア算出式

risk_score =
((w_cvss × normalized_cvss)
+ (w_epss × epss_percentile)
+ kev_bonus
+ exploit_bonus)
× context_multiplier

---

## 5.2 デフォルト重み（設定ファイルで変更可能）

| パラメータ | 値 |
|------------|----|
| w_cvss | 0.5 |
| w_epss | 0.3 |
| kev_bonus | +0.2 |
| exploit_bonus | +0.1 |

---

## 5.3 正規化ルール

- normalized_cvss = CVSS / 10
- epss_percentile = 0–1
- CVSS未取得 → N/A明示（w_cvss項は0）
- EPSS未取得 → N/A明示（w_epss項は0）
- KEV該当は最低Highへ昇格

---

## 5.4 コンテキスト倍率（上限2.0 / 下限0.5）

| 条件 | 倍率 |
|------|------|
| internet_exposed=true | ×1.2 |
| internet_exposed=false | ×0.8 |
| data_sensitivity=high | ×1.3 |
| data_sensitivity=medium | ×1.1 |
| environment=production | ×1.2 |
| environment=dev | ×0.9 |

---

## 5.5 risk_score → severity変換

| risk_score | severity |
|------------|----------|
| >= 0.85 | Critical |
| >= 0.65 | High |
| >= 0.40 | Medium |
| >= 0.20 | Low |
| < 0.20 | Info |

---

# 6. コンテキスト入力

- deployment_type: k8s / vm / serverless
- internet_exposed: true / false
- data_sensitivity: low / medium / high
- environment: production / staging / dev

入力不足時は conservative評価し、Assumptionをレポートに明示。

---

# 7. confidence算出ロジック

confidence = signal_strength × evidence_quality

## 7.1 signal_strength

| 判定タイプ | 値 |
|------------|----|
| SBOM一致 | 0.95 |
| CVE厳密一致 | 0.90 |
| 設定完全一致 | 0.90 |
| パターン検知 | 0.70 |
| ヒューリスティック | 0.55 |

## 7.2 evidence_quality

| 証拠レベル | 係数 |
|------------|------|
| file+line+snippet | ×1.0 |
| fileのみ | ×0.9 |
| 文字列一致のみ | ×0.8 |
| 推測含む | ×0.7 |

---

# 8. 品質KPI

- 誤検知率 < 5%
- suppress率 < 15%
- High以上の妥当率 > 90%
- PR平均スキャン時間 < 2分（中規模）

---

# 9. 抑制機構

## 9.1 コード内抑制

# oss-risk-ignore: RULE_ID

## 9.2 suppressファイル

oss-risk-ignore.yml

- rule_id
- justification
- expiry_date
- approver
- ticket

期限切れは自動再有効化。

---

# 10. パフォーマンス設計

## 10.1 SLO

| 規模 | 目標時間 |
|------|----------|
| <50 deps | <30秒 |
| <300 deps | <2分 |
| <1000 deps | <5分 |

## 10.2 実装要件

- 並列API呼び出し
- キャッシュ機構
- 差分優先解析
- レート制限対応

---

# 11. リスクカテゴリ

## A. 依存関係

### A-0 SBOM完全解析
- CycloneDX生成
- 推移依存列挙

### A-1 既知脆弱性
優先順位：
1. CISA KEV
2. GitHub Advisory
3. OSV
4. NVD

### A-2 バージョン未固定
### A-3 署名未検証

---

## B. CI/CD

### B-1 Actions SHA未固定
### B-2 過剰権限
### B-3 Docker digest未固定
### B-4 curl | bash

---

## C. アプリケーション

### C-1 root実行
### C-2 秘密情報検出
### C-3 危険API使用
### C-4 CORS全許可

---

## D. ガバナンス

### D-1 更新停止（12ヶ月）
### D-2 Bus Factor 1
### D-3 セキュリティ運用不在
### D-4 修正遅延（90日超）

---

## E. ライセンス

- GPL/AGPL
- 非互換混在
- LICENSE未定義

---

## F. ネットワーク

- debug=true
- HTTPのみ
- /admin公開可能性

---

# 12. 複合リスク昇格

Critical昇格条件：

- write-all + self-hosted runner
- curl|bash + root
- KEV + internet_exposed
- debug=true + HTTP

---

# 13. 差分管理

- baseline.json保存
- 新規のみ通知
- severity上昇は再通知
- MITIGATED履歴保持

---

# 14. Risk Acceptance

状態：

- OPEN
- ACCEPTED
- MITIGATED
- FALSE_POSITIVE

承認ログ保持（approver, justification, ticket, timestamp）。

---

# 15. 出力仕様

## JSON

- category
- rule_id
- severity
- risk_score
- confidence
- evidence
- remediation
- cvss
- epss
- kev_flag
- exploit_available
- context
- status
- source
- scan_mode
- scan_timestamp
- coverage

---

## Markdownレポート

- Executive Summary
- Critical一覧
- 新規リスク
- SLA超過
- KEV一覧
- 修正優先度
- Assumption

---

## SBOM出力

CycloneDX形式

---

## PRコメント

差分のみ出力
High以上ブロック可能（設定可）

---

# 16. SLA管理

| Severity | 修正期限 |
|----------|----------|
| Critical | 7日 |
| High | 30日 |
| Medium | 90日 |

期限超過は警告。

---

# 17. 運用フロー

1. PR作成
2. PRモード実行
3. High以上レビュー
4. 必要ならACCEPTED登録
5. Nightlyフルスキャン
6. SLA追跡
7. 月次レポート

---

# 18. 監査対応

- 判定ロジック明文化
- データソース明示
- suppress履歴保持
- 受容ログ保存
- 変更履歴追跡
- 監査モード全履歴出力

---

# 19. 将来拡張

- Kubernetes診断
- Terraform解析
- SLSA評価
- OSSF Scorecard統合
- SBOM差分比較
- Exploit DB統合

---

# 20. ゴール

本仕様は以下用途に耐える：

- 内部セキュリティレビュー
- OSS導入審査
- 監査証跡提出
- DevSecOps統合
- エンタープライズ運用
