---
title: "ノーコードAIツール（Dify/n8n/Flowise）のプロンプトインジェクション対策"
emoji: "🔒"
type: "tech"
topics: ["dify", "n8n", "nocode", "llm", "security"]
published: false
---

Dify・n8n・Flowise・BotpressなどのノーコードAIツールでRAGアプリを作る場合も、プロンプトインジェクション対策は必須です。

## ノーコードツールが特に危険な理由

1. **入力サニタイズが設定できない** — GUIでは細かいバリデーション設定が困難
2. **取得コンテンツがそのままLLMへ** — Web検索・DB取得結果を直接LLMに渡す
3. **エラーハンドリングが薄い** — 攻撃成功時の影響範囲が大きい

## Dify での実装

Dify の HTTP Request ノードを使って、LLMへ渡す前に jpi-guard を呼ぶ。

```yaml
# Difyワークフロー例
1. User Input → HTTP Request (jpi-guard /v1/cleanse)
               ↓ injection_detected: false の場合のみ
2. → Vector DB Retrieval
3. → LLM Generate
```

HTTPリクエスト設定：

```
URL: https://api.nexus-api-lab.com/v1/external-content-cleanse
Method: POST
Headers: Authorization: Bearer {{ENV.JPI_GUARD_API_KEY}}
Body: {"content": "{{user_input}}", "strictness": "medium"}
```

## n8n での実装

n8n-nodes-jpi-guard（近日公開）を使うと、ワークフローに1ノードで追加できます。

```
[Webhook] → [jpi-guard: Check Injection]
              ├── Safe → [OpenAI: Generate]
              └── Injection Detected → [Set: "不正なリクエストを検出しました"]
```

## まとめ

ノーコードAIを使っている場合でも、入力バリデーションとして jpi-guard API を組み込むことで、プロンプトインジェクションリスクを大幅に低減できます。

無料トライアルで試す → https://jpi-guard.nexus-api-lab.workers.dev/
