---
title: "チャットボットの入力検証を安全にする実装パターン — LLMセキュリティ入門"
emoji: "🤖"
type: "tech"
topics: ["chatbot", "llm", "security", "validation", "typescript"]
published: false
---

チャットボットを本番公開する前に必ず実装すべき入力検証パターンを解説します。

## 問題: バリデーションだけでは不十分

```typescript
// ❌ 不十分な実装 — 文字数と型だけチェック
function validateInput(input: string): boolean {
  if (input.length > 2000) return false;
  if (typeof input !== 'string') return false;
  return true; // これだけでは攻撃を防げない
}
```

## 正しい実装: 4層防御

```typescript
import { JpiGuard } from 'jpi-guard';

const guard = new JpiGuard({ apiKey: process.env.JPI_GUARD_API_KEY });

async function validateChatInput(input: string, userId: string): Promise<string> {
  // Layer 1: 基本バリデーション
  if (!input || input.length > 4000) {
    throw new ValidationError('Invalid input length');
  }

  // Layer 2: プロンプトインジェクション検出
  const guardResult = await guard.check(input, {
    strictness: 'medium',  // 誤検知とのバランス
    language: 'auto'       // JA/EN 自動判定
  });

  if (guardResult.injection_detected && guardResult.risk_score > 0.7) {
    // 高リスクは拒否
    throw new SecurityError(`Potential injection detected (score: ${guardResult.risk_score})`);
  }

  // Layer 3: PII検出（オプション）
  // const piiResult = await piiGuard.check(input);

  // Layer 4: レート制限
  await rateLimiter.check(userId);

  return guardResult.cleaned_content ?? input;
}
```

## fail-open vs fail-close

APIが一時的に使えない場合の動作を設計段階で決める。

```typescript
const guard = new JpiGuard({
  apiKey: process.env.JPI_GUARD_API_KEY,
  onTimeout: 'fail_open',  // 本番推奨: タイムアウト時は通す
  // onTimeout: 'fail_close',  // 高セキュリティ: タイムアウト時も拒否
  timeout: 150,  // ms
});
```

## まとめ

- 文字数チェックだけでは不十分。プロンプトインジェクション検出を必ず追加する
- fail-open / fail-close の選択はビジネス要件に応じて設計段階で決定する
- Layer 2（注入検出）だけでも大きな効果がある

無料で始める → https://jpi-guard.nexus-api-lab.workers.dev/
