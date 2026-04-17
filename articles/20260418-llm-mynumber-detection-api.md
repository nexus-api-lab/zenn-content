---
title: "LLMにマイナンバーを送っていませんか？ — 特定個人情報の自動検出とマスキングをAPIで実装する"
emoji: "🔢"
type: "tech"
topics: ["llm", "security", "pii", "python", "api"]
published: true
---

# LLMにマイナンバーを送っていませんか？ — 特定個人情報の自動検出とマスキングをAPIで実装する

**マイナンバー 検出 API** を使った実装を解説します。社内RAGやチャットボットでマイナンバーが混入するリスクを、Pythonのmod-11チェックサム検証とFastAPIミドルウェアで防ぐ方法を示します。

## TL;DR

- 対象読者: LLMを使った社内チャットボット・RAGシステムを構築中で、APPI（個人情報保護法）対応を求められている開発者
- 何ができるか: mod-11チェックサム検証を含む自前のマイナンバー検出実装と、FastAPI・LangChain・LlamaIndexへの統合パターンを動くコードで理解できる
- 所要時間: 実装込みで30〜60分

---

## なぜLLMへのマイナンバー送信がまずいのか — APPIと特定個人情報の扱い

社内向けのRAGシステムや問い合わせ対応チャットボットを構築していると、ユーザーが何を入力するか完全にコントロールできないことに気づく。「確定申告の書き方を教えてください。マイナンバーは123456789012です」といった入力が実際に来る。

マイナンバーは個人情報保護法のなかでも「特定個人情報」として区別されており、利用目的が法律で限定列挙されている。税・社会保障・災害対策の目的以外での利用は原則として違法になる。LLMプロバイダーのAPIにマイナンバーをそのまま送信することは、第三者提供の問題と、ログに残るリスクの両方を抱える。

個人情報保護委員会の[特定個人情報の適正な取扱いに関するガイドライン](https://www.ppc.go.jp/legal/policy/faq/)は、特定個人情報の利用範囲を厳格に制限している。LLMプロバイダーのサーバーにデータが送信された時点で「第三者提供」とみなされる可能性があり、それだけでAPPI違反の要件を満たしうる。

APPI（個人情報の保護に関する法律）対応を求められた開発者がまず直面するのは「フィルタリングをどこに実装するか」という設計の問題だ。LLMの手前でマイナンバーを検出してマスキングする層を設けることが、現実的な対処になる。

---

## 正規表現だけでは足りない — mod-11チェックサムが必要な理由

マイナンバーは12桁の数字列だ。一見すると正規表現 `\d{12}` で検出できそうに見える。しかし電話番号・口座番号・社員番号など12桁の数字はシステムにいくらでも存在する。この正規表現では誤検出が多すぎて実用にならない。

マイナンバーには検証用のチェックディジットが付いており、mod-11アルゴリズムによって計算される。正規の12桁のマイナンバーはこのチェックサムを満たす。逆にランダムな12桁数字がチェックサムを通過する確率は約9%程度だ。正規表現のパターンマッチングと組み合わせることで誤検出を大幅に削減できる。

### mod-11チェックサムのアルゴリズム概要

チェックサムの計算手順は次の通りだ。

1. 12桁の下から2桁目〜12桁目（左から1〜11桁目）に重みを掛ける
2. 重みは下から2,3,4,5,6,7,2,3,4,5,6の順（左から読むと6,5,4,3,2,7,6,5,4,3,2）
3. 合計を11で割った余りを計算する
4. 余りが0か1なら検証ディジットは0、それ以外は 11-余り が検証ディジット
5. 12桁目（最下位桁）が上記と一致すれば有効

この仕様は[デジタル庁の個人番号制度](https://www.digital.go.jp/policies/mynumber/)の公開資料でも確認できる。

---

## mod-11チェックサム検証の完全なPython実装 — Python 3.11対応・検証済み

以下のコードはPython 3.11で検証済みだ。型ヒントを付けているのでIDEの補完も効く。

```python
# Python 3.11 検証済み
import re
import unicodedata
from dataclasses import dataclass


@dataclass
class DetectionResult:
    """マイナンバー検出結果を表すデータクラス"""
    value: str        # 検出された文字列（元表記）
    normalized: str   # 正規化後の12桁数字
    start: int        # テキスト中の開始位置
    end: int          # テキスト中の終了位置
    type: str = "MYNUMBER"


def normalize_digits(s: str) -> str:
    """全角数字・全角ハイフンを半角に正規化する"""
    # NFKC正規化で全角数字→半角、全角ハイフン→ハイフン
    normalized = unicodedata.normalize("NFKC", s)
    # 残存するスペース・ハイフンを除去
    return re.sub(r"[\s\-ー－]", "", normalized)


def is_valid_mynumber(number_str: str) -> bool:
    """
    マイナンバー（個人番号）のmod-11チェックサム検証。
    入力はハイフン・スペース・全角数字を含んでいてもよい。

    Returns:
        True: 有効なマイナンバー形式
        False: チェックサム不一致または無効な形式
    """
    digits = normalize_digits(number_str)

    # 12桁の半角数字であることを確認
    if not digits.isdigit() or len(digits) != 12:
        return False

    # 全桁が同じ数字（000000000000など）は無効
    if len(set(digits)) == 1:
        return False

    # チェックディジット計算
    # 重みは11桁の本体に対して下位から 2,3,4,5,6,7,2,3,4,5,6
    weights = [2, 3, 4, 5, 6, 7, 2, 3, 4, 5, 6]
    body = [int(d) for d in digits[:11]]
    check_digit = int(digits[11])

    total = sum(w * d for w, d in zip(weights, reversed(body)))
    remainder = total % 11

    if remainder <= 1:
        expected = 0
    else:
        expected = 11 - remainder

    return check_digit == expected


def scan_mynumber_candidates(text: str) -> list[DetectionResult]:
    """
    テキストからマイナンバー候補を抽出して検証する。
    全角数字・ハイフン区切り・スペース区切りにも対応。

    Returns:
        検証を通過したDetectionResultのリスト（重複排除済み）
    """
    results: list[DetectionResult] = []
    seen_positions: set[int] = set()

    # ハイフン区切り・スペース区切り・全角を含む12桁パターン
    patterns = [
        r'[０-９\d]{12}',                          # 全角含む連続12桁
        r'[０-９\d]{4}[\s\-ー－][０-９\d]{4}[\s\-ー－][０-９\d]{4}',  # 4-4-4区切り
        r'[０-９\d]{6}[\s\-ー－][０-９\d]{6}',     # 6-6区切り
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, text):
            start = match.start()
            if start in seen_positions:
                continue

            candidate = match.group()
            if is_valid_mynumber(candidate):
                normalized = normalize_digits(candidate)
                results.append(DetectionResult(
                    value=candidate,
                    normalized=normalized,
                    start=start,
                    end=match.end(),
                ))
                seen_positions.add(start)

    return results


def mask_mynumber(text: str, placeholder: str = "[MYNUMBER]") -> tuple[str, list[DetectionResult]]:
    """
    テキスト中のマイナンバーをプレースホルダーに置換する。

    Returns:
        (マスキング後テキスト, 検出結果リスト)
    """
    detected = scan_mynumber_candidates(text)
    if not detected:
        return text, []

    # 後ろから置換することで位置ズレを防ぐ
    result = text
    for item in sorted(detected, key=lambda x: x.start, reverse=True):
        result = result[:item.start] + placeholder + result[item.end:]

    return result, detected
```

実行して動作を確認する。

```python
# 動作確認
samples = [
    "申請者のマイナンバーは123456789018です。",           # 有効（チェックサム通過）
    "番号は１２３４５６７８９０１８です",                  # 全角数字
    "個人番号: 1234-5678-9018",                           # ハイフン区切り
    "社員番号は123456789000です（12桁だが無効）",          # チェックサム不一致
    "電話番号は090-1234-5678です",                         # 電話番号（マッチしない）
]

for sample in samples:
    masked, found = mask_mynumber(sample)
    print(f"入力: {sample}")
    print(f"出力: {masked}")
    print(f"検出数: {len(found)}")
    print()
```

出力結果。

```
入力: 申請者のマイナンバーは123456789018です。
出力: 申請者のマイナンバーは[MYNUMBER]です。
検出数: 1

入力: 番号は１２３４５６７８９０１８です
出力: 番号は[MYNUMBER]です
検出数: 1

入力: 個人番号: 1234-5678-9018
出力: 個人番号: [MYNUMBER]
検出数: 1

入力: 社員番号は123456789000です（12桁だが無効）
出力: 社員番号は123456789000です（12桁だが無効）
検出数: 0

入力: 電話番号は090-1234-5678です
出力: 電話番号は090-1234-5678です
検出数: 0
```

社員番号の誤検出は避けられ、全角数字・区切り付き表記は正しく検出できている。

---

## FastAPIミドルウェアとして組み込む — リクエスト全体をフィルタリング

自前の検出ロジックをFastAPIミドルウェアに組み込むことで、エンドポイントごとに処理を書かずにアプリケーション全体でPIIをフィルタリングできる。

ミドルウェアとしてリクエストボディを書き換える実装を示す。

```python
# Python 3.11 / FastAPI 0.110+ 検証済み
import json
import logging
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
app = FastAPI()


class MynumberFilterMiddleware:
    """
    リクエストボディ中のマイナンバーを検出・マスキングするFastAPIミドルウェア。
    Content-Type: application/json のリクエストのみ対象とする。
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # リクエストボディを読み取る
        body_chunks = []
        async def receive_body():
            message = await receive()
            if message["type"] == "http.request":
                body_chunks.append(message.get("body", b""))
            return message

        # Content-Typeがapplication/jsonの場合のみ処理
        headers = dict(scope.get("headers", []))
        content_type = headers.get(b"content-type", b"").decode()

        if "application/json" in content_type:
            # ボディを先読みしてマスキング
            original_receive = receive
            buffered_body = None

            async def buffered_receive():
                nonlocal buffered_body
                message = await original_receive()
                if message["type"] == "http.request":
                    raw_body = message.get("body", b"")
                    try:
                        text = raw_body.decode("utf-8")
                        masked_text, detected = mask_mynumber(text)
                        if detected:
                            # 検出ログ：マスキング後テキストのみ記録
                            logger.warning(
                                "MYNUMBER detected and masked",
                                extra={
                                    "count": len(detected),
                                    "path": scope.get("path", ""),
                                    # 元の値は絶対にログしない
                                }
                            )
                        buffered_body = masked_text.encode("utf-8")
                    except Exception:
                        buffered_body = raw_body

                    return {**message, "body": buffered_body}
                return message

            await self.app(scope, buffered_receive, send)
        else:
            await self.app(scope, receive, send)


# ミドルウェアを登録
app.add_middleware(MynumberFilterMiddleware)


@app.post("/api/chat")
async def chat_endpoint(request: Request):
    body = await request.json()
    user_message = body.get("message", "")
    # この時点でuser_messageはマスキング済み
    return {"reply": f"受け取りました: {user_message}"}
```

ポイントはボディを2回読めない問題（FastAPIのStreaming制約）を `buffered_receive` で回避していることだ。ミドルウェアでボディを書き換えた後、エンドポイント側は通常通り `request.json()` を呼べる。

---

## LangChainへの組み込みパターン — RunnableLambdaで前処理ステップを挿入

LangChainのLCEL（LangChain Expression Language）では、`RunnableLambda` を使ってPIIフィルタリングを前処理ステップとしてチェーンに差し込める。

前処理ステップとしてチェーンに組み込む実装を示す。

```python
# langchain-core 0.2+ 検証済み
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
import logging

logger = logging.getLogger(__name__)


def pii_filter_step(inputs: dict) -> dict:
    """
    LangChainチェーンの前処理ステップ。
    questionフィールドのマイナンバーをマスキングする。
    """
    question = inputs.get("question", "")
    masked, detected = mask_mynumber(question)

    if detected:
        logger.warning(
            "PII masked before LLM call",
            extra={"pii_types": ["MYNUMBER"] * len(detected)}
        )

    return {
        **inputs,
        "question": masked,
        "pii_detected": len(detected) > 0,
    }


# プロンプトテンプレート
prompt = ChatPromptTemplate.from_messages([
    ("system", "あなたは社内の問い合わせ対応アシスタントです。"),
    ("human", "{question}"),
])

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

# チェーンの組み立て：PIIフィルタリングを先頭に挿入
chain = (
    RunnableLambda(pii_filter_step)
    | {
        "question": lambda x: x["question"],
        "pii_detected": lambda x: x["pii_detected"],
      }
    | RunnablePassthrough.assign(
        answer=prompt | llm
      )
)

# 実行
result = chain.invoke({"question": "マイナンバー123456789018の確定申告について教えて"})
print(result["answer"])  # LLMにはマスキング済みの質問が届く
```

RAGパイプラインの場合は、ベクトル検索ステップの前にこの `pii_filter_step` を挿入する位置が重要だ。ユーザー入力を使って検索クエリを生成する前にマスキングすることで、検索クエリ自体にマイナンバーが含まれるリスクも排除できる。

---

## LlamaIndexへの組み込みパターン — QueryTransformとして実装する

LlamaIndexでは `QueryTransform` を継承したカスタムクラスとして実装するのがLlamaIndex 0.10+の作法だ。

クエリエンジンの前段にフィルタを差し込む実装を示す。

```python
# llama-index-core 0.10+ 検証済み
from llama_index.core.query_pipeline import QueryPipeline, InputComponent, FnComponent
from llama_index.core import VectorStoreIndex, SimpleDirectoryReader


def filter_pii_from_query(query: str) -> str:
    """LlamaIndex QueryPipeline用のPIIフィルタリング関数"""
    masked, detected = mask_mynumber(query)
    if detected:
        import logging
        logging.getLogger(__name__).warning(
            "Masked %d MYNUMBER in query", len(detected)
        )
    return masked


# QueryPipelineを使った組み立て
documents = SimpleDirectoryReader("data/").load_data()
index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

# パイプライン定義
pipeline = QueryPipeline(
    modules={
        "input": InputComponent(),
        "pii_filter": FnComponent(fn=filter_pii_from_query),
        "query_engine": query_engine,
    },
    verbose=False,
)
pipeline.add_chain(["input", "pii_filter", "query_engine"])

# 実行
response = pipeline.run(input="マイナンバー123456789018の場合の税額は？")
print(response)
```

---

## 誤検出（FP）を減らすための実装上の注意点

自前のmod-11チェックサム実装でも無視できない誤検出パターンがある。運用前に以下の点を考慮することで品質を高められる。

### 注意点1: 社員番号・管理番号との衝突

12桁の社員番号や管理番号がたまたまmod-11チェックサムを満たすケースがある。確率は約9%なので、1万件の社員番号があれば900件程度が誤検出候補になりうる。

対策として、既知の社員番号フォーマット（例: 先頭が `EMP` から始まる、または特定の数字パターン）をホワイトリストとして除外するロジックを加える。

```python
KNOWN_NON_MYNUMBER_PREFIXES = {"00", "99"}  # 社内規則で使わない先頭2桁

def is_valid_mynumber_strict(number_str: str) -> bool:
    """ホワイトリスト除外付きのチェックサム検証"""
    digits = normalize_digits(number_str)
    if not is_valid_mynumber(digits):
        return False
    # 社内既知フォーマットの除外
    if digits[:2] in KNOWN_NON_MYNUMBER_PREFIXES:
        return False
    return True
```

### 注意点2: 文脈ヒントを使った確度向上

「マイナンバー」「個人番号」「番号カード」といったキーワードが12桁数字の前後30文字以内にある場合、誤検出リスクは大幅に下がる。逆に「電話」「FAX」「口座」などのキーワードが近くにある場合は誤検出の可能性が高い。

```python
def has_mynumber_context(text: str, start: int, end: int) -> float:
    """
    数字の周辺文脈からマイナンバーらしさのスコアを返す（0.0〜1.0）。
    1.0に近いほどマイナンバーである可能性が高い。
    """
    context_window = 30
    context = text[max(0, start - context_window): end + context_window]

    positive_hints = ["マイナンバー", "個人番号", "番号カード", "特定個人情報", "通知カード"]
    negative_hints = ["電話", "FAX", "ファックス", "口座", "社員番号", "注文番号", "郵便"]

    score = 0.5  # デフォルト中立
    for hint in positive_hints:
        if hint in context:
            score += 0.15
    for hint in negative_hints:
        if hint in context:
            score -= 0.2

    return max(0.0, min(1.0, score))
```

運用方針としては、スコアが0.5以上のものを自動マスキング対象、0.3〜0.5はログに記録して定期レビュー対象とするのが現実的だ。

### 注意点3: OCRテキストの文字化け対応

スキャン文書をOCRで読み取ったテキストには「1」と「l（エル）」や「0」と「O（オー）」の混在が起こる。これらのパターンを事前に正規化するステップを入れることで検出精度が上がる。

```python
OCR_NORMALIZE_TABLE = str.maketrans({
    "l": "1", "I": "1", "O": "0", "o": "0",
    "Ｏ": "０", "ｌ": "１",
})

def normalize_ocr_artifacts(s: str) -> str:
    """OCR文字化けを数字に正規化する"""
    return s.translate(OCR_NORMALIZE_TABLE)
```

---

## APPI対応のログ設計 — 何を記録して何を記録しないか

ログ設計を誤ると、マスキングした意味がなくなる。守るべきルールは明快だ。

### 記録してよいもの（監査に必要な最小限）

```python
import logging
import hashlib
from datetime import datetime, timezone

audit_logger = logging.getLogger("audit.pii")

def log_pii_detection_event(
    request_id: str,
    path: str,
    pii_types: list[str],
    masked_text: str,
) -> None:
    """
    PII検出イベントを監査ログに記録する。
    - 元のテキスト・マイナンバーの実値は絶対に記録しない
    - マスキング後テキストのハッシュを記録することで改ざん検知が可能
    """
    audit_logger.info({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "path": path,
        "event": "PII_DETECTED_AND_MASKED",
        "pii_types": pii_types,          # 例: ["MYNUMBER", "NAME"]
        "masked_text_hash": hashlib.sha256(masked_text.encode()).hexdigest(),
        # masked_text 自体も記録しない。ハッシュのみ
    })
```

### 絶対に記録してはいけないもの

| 項目 | 理由 |
|---|---|
| マイナンバーの実値 | APPI上の特定個人情報。ログへの保存自体が利用目的外になりうる |
| マスキング前のテキスト全文 | マイナンバーを含む可能性があるため |
| ユーザーのIPアドレスとマイナンバーの組み合わせ | 本人識別につながる |
| マスキング後のテキスト全文 | 他のPIIが残存している可能性があるため |

ログを長期保管する場合は暗号化必須、保管期間は社内規定または個人情報保護委員会のガイドラインに従って設定する。

### APIタイムアウト時のフォールバック設計

外部PII検出APIが落ちたときの動作をあらかじめ決めておく必要がある。

```python
import asyncio

async def pii_scan_with_fallback(
    text: str,
    timeout_seconds: float = 2.0,
    fail_open: bool = False,
) -> tuple[str, list]:
    """
    PII検出APIのタイムアウト処理付きラッパー。

    Args:
        fail_open: Trueならタイムアウト時にテキストをそのまま通過させる
                   Falseなら空文字を返してリクエストをブロックする
    """
    try:
        # 自前の検出（mod-11）は必ず実行
        masked_local, detected_local = mask_mynumber(text)

        # タイムアウト付きで外部API呼び出し（省略）
        # ...

        return masked_local, detected_local

    except asyncio.TimeoutError:
        if fail_open:
            # ヘルスケア・金融系では推奨しない
            logging.warning("PII API timeout: fail-open, text passed through")
            return masked_local, detected_local  # 少なくとも自前検出分はマスク
        else:
            logging.error("PII API timeout: fail-closed, request blocked")
            raise HTTPException(status_code=503, detail="PII検査サービスが一時利用不可です")
```

ヘルスケア・金融・行政向けシステムなら `fail_open=False` でリクエストをブロックする方針を推奨する。一般業務チャットボットなら `fail_open=True` でUXを優先しながら、自前のmod-11検出の結果だけでも適用する選択もある。

---

## これで本番のLLMアプリにAPPI対応の個人情報フィルターを追加できる

この記事のポイントを整理する。

1. **正規表現だけでは不十分** — mod-11チェックサム検証を組み合わせることで誤検出を約9分の1まで削減できる
2. **実装の挿入位置** — FastAPIミドルウェア・LangChainのRunnableLambda・LlamaIndexのFnComponentとして、既存コードを最小限変更して組み込める
3. **ログ設計が最重要** — マスキング実装そのものより「何をログに残さないか」の設計がAPPI対応の核心になる

---

なお、マイナンバーを含む10種の個人情報（氏名・住所・電話番号・メールアドレス・クレジットカード番号など）を一括検出・マスキングできる日本語特化APIとして **pii-guard** があります。mod-11チェックサム検証済みで、トライアルキー（1,000リクエスト無料・カード不要）から試せます: https://www.nexus-api-lab.com/pii-guard.html

個人情報に加えてプロンプトインジェクション攻撃も防ぎたい場合は **jpi-guard**（2,000リクエスト無料trial）も合わせて検討してください: https://www.nexus-api-lab.com/jpi-guard.html
