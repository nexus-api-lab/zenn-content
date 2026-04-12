---
title: "生成AIセキュリティスタートアップが日本に登場 — Prompt Security撤退後の空白を埋める"
emoji: "🏢"
type: "idea"
topics: ["llm", "security", "startup", "ai", "saas"]
published: false
published_at: "2026-04-13 09:00"
---

2025年8月、プロンプトインジェクション防御の代表格だったPrompt SecurityがSentinelOneに$250Mで買収されました。その結果、SME・開発者向け市場に巨大な空白が生まれました。

## 市場の現状

```
$100K+/年  → Cisco AI Defense / Palo Alto XSIAM / SentinelOne
           ↑ ← 大企業向け
─────────────────────────────── ← ここに巨大な空白
           ↓ ← 中小・スタートアップ向け
¥4,900/月  → jpi-guard（日本発）
```

日本市場では特殊な状況が重なっています：

- 日本語RAGアプリが急増（政府・金融・医療での生成AI活用）
- 日本語特有の攻撃手法（全角バイパス・丁寧語擬装）に対応する製品がない
- AI事業者ガイドライン第1.2版でセキュリティ確保が実質必須化

## jpi-guardの技術的差別化

| 特徴 | 詳細 |
|---|---|
| 日本語ネイティブ | 全角/半角変換・異体字・Zero-width文字・丁寧語パターンに対応 |
| エッジ処理 | Cloudflare Workers上で動作。入力データをサーバーに保存しない |
| <50ms | Stage1（ルールベース）: 平均31ms。LLM推論を使わない |
| 段階的移行 | 月¥4,900から始め、実際の攻撃を確認してからアップグレード |

## 実際に試す方法

```bash
# あなたのRAGエンドポイントをテスト
npx pijack test https://your-rag-api.example.com
```

詳細: https://jpi-guard.nexus-api-lab.workers.dev/
