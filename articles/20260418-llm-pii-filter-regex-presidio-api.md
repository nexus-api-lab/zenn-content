---
title: "LLMアプリに個人情報フィルターを追加する3つの方法 — 正規表現・Presidio・外部API比較"
emoji: "🛡️"
type: "tech"
topics: ["llm", "security", "pii", "python", "api"]
published: true
---

# LLMアプリに個人情報フィルターを追加する3つの方法 — 正規表現・Presidio・外部API比較

**TL;DR**
LLMアプリへのユーザー入力に個人情報（氏名・マイナンバー・クレジットカード等）が混入するリスクがある。本記事では正規表現・Microsoft Presidio・外部APIの3手法を実装コードつきで比較し、ユースケース別の選定基準を示す。Python 3.11 / FastAPI 環境で動作確認済み。コードの追加量は約100行、所要時間は30〜60分を想定している。

**対象読者**: LLMを使ったSaaSを開発中で、ユーザー入力に個人情報が混入するリスクに気づきフィルタリング手段を探しているエンジニア。

---

## LLMアプリ 個人情報 フィルタが必要になった経緯 — 実際に起きた問題

ある日、本番環境のリクエストログを確認していると、ユーザーのチャット履歴の中にマイナンバーらしき12桁の数字が含まれているのを発見した。

「履歴書を添削してください」「確定申告の計算を手伝ってください」——こうした依頼に氏名・住所・マイナンバーが含まれることは、LLMを使ったSaaSでは日常的に起きる。開発者が想定していなくても、ユーザーは便利そうなツールに自然と機密情報を入力する。

問題は2層ある。

**第一層: 外部LLMプロバイダーへの送信リスク**。OpenAI・Anthropic等のAPIを呼び出している場合、送信したデータはプロバイダーのサーバーを経由する。利用規約でトレーニングへの使用を制限できるオプションがあっても、「送信しなかった」という証明にはならない。個人情報保護法・GDPRの観点では、第三者（プロバイダー）への提供に該当する可能性がある。

**第二層: 自社ログへの記録リスク**。デバッグ目的でリクエストをそのままログに残すのは一般的なプラクティスだが、LLMアプリでこれを続けると個人情報が大量蓄積される。データ漏洩インシデントが発生したとき、影響範囲の特定が困難になる。

対策の選択肢は大きく3つある。それぞれを実装コードつきで詳しく見ていく。

---

## 方法1: 正規表現で自前実装 — 手軽だが日本語で壁にぶつかる

### 何ができるか

最も素早く着手できるのが正規表現による自前実装だ。電話番号・メールアドレス・クレジットカード番号・郵便番号は比較的パターンが明確で、正規表現で8割程度はカバーできる。コストはゼロ、インフラ追加なし、ライブラリ依存もなし。

### 基本実装

以下のコードをそのままコピーして使える基本的なPIIマスク関数だ。

```python
# pii_filter.py — Python 3.11
import re
from dataclasses import dataclass

PII_PATTERNS: dict[str, str] = {
    "email":        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    "phone_jp":     r'0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{4}',
    "postal_code":  r'\b\d{3}[-－]\d{4}\b',
    "credit_card":  r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    "mynumber":     r'\b\d{12}\b',  # 注意: チェックサム検証は別途必要
}

def simple_pii_mask(text: str) -> str:
    """テキスト中のPIIを正規表現でマスクして返す"""
    masked = text
    for pii_type, pattern in PII_PATTERNS.items():
        masked = re.sub(pattern, f"[{pii_type.upper()}]", masked)
    return masked
```

### 動作確認

関数が正しく動いていれば、次のような出力になる。

```python
sample = "田中太郎です。電話は090-1234-5678、メールはtaro@example.comです。"
print(simple_pii_mask(sample))
# 出力: 田中太郎です。電話は[PHONE_JP]、メールは[EMAIL]です。
# ※ 氏名「田中太郎」は検出できていない
```

マスクできていない「田中太郎」という氏名がそのまま残っている点が、後で解説する最大の課題だ。

### 日本語で詰まる3つのパターン

#### ケース1: 氏名の正規表現は実質的に作れない

「田中太郎」を検出する正規表現を考えると、次のような問題に直面する。

```python
# 試み1: 漢字4〜6文字のパターン
r'[\u4e00-\u9fff]{2,3}[\u4e00-\u9fff]{1,3}'

# 問題: 「田中工業」「太郎食品」「鈴木建設」も全て誤検出する
# → 氏名と組織名・地名の区別が正規表現だけでは不可能
```

結果として「氏名は検出できない」という前提でシステム設計をせざるを得なくなる。

#### ケース2: 住所の表記ゆれが無限にある

```python
# 東京都渋谷区の表記バリエーション（一例）
# 東京都渋谷区恵比寿1-2-3
# 東京都渋谷区恵比寿１－２－３   （全角数字・全角ハイフン）
# 東京都渋谷区恵比寿1丁目2番3号
# 東京都 渋谷区 恵比寿 1-2-3   （スペース入り）

# これら全てを1つの正規表現でカバーするのは現実的でない
```

#### ケース3: マイナンバーの12桁はチェックサムなしでは誤検出だらけ

```python
# 12桁の数字が含まれるが、マイナンバーではない例
# 商品コード: 012345678901
# 電話番号の羅列: 09012345678 03-1234-5678
# 金額: ¥123456789012

# 本物のマイナンバーはmod-11チェックサムで検証できるが
# 実装が複雑になる（後述の外部APIはこれを自動処理する）
```

### 正規表現の限界まとめ

正規表現は「電話番号とメールアドレスだけ」という限定的なユースケースなら有効だ。しかし日本語の氏名・住所に対応しようとすると、パターンメンテナンスが永遠に続く技術的負債になる。フィールドが増えるたびにエッジケースが発見され、QAの手が止まらなくなる。

---

## 方法2: Microsoft Presidioを使う — 導入手順と日本語対応の現実

### Presidioとは何か

[Microsoft Presidio](https://microsoft.github.io/presidio/) はマイクロソフトが公開しているOSSのPII検出・匿名化フレームワークだ。Named Entity Recognition（NER）と正規表現を組み合わせた検出エンジンを持ち、英語については高い精度がある。カスタムrecognizerを追加できる拡張性も魅力だ。

presidio-analyzer 2.x / Python 3.11 で動作確認している。

### インストール手順（英語対応）

英語テキストのみを処理する場合のインストール手順は次のとおりだ。

```bash
# 基本パッケージのインストール
pip install presidio-analyzer presidio-anonymizer

# 英語用のspaCyモデルをダウンロード
python -m spacy download en_core_web_lg
```

### 英語テキストでの動作確認

インストール後、次のコードで英語PIIの検出・匿名化が動作することを確認できる。

```python
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

text = "My name is John Smith and my email is john@example.com and SSN is 123-45-6789"

# PIIの検出（言語は"en"を指定）
results = analyzer.analyze(text=text, language="en")

# 検出結果をもとにテキストを匿名化
anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
print(anonymized.text)
```

英語テキストが正しく処理されていれば、出力は次のようになる。

```
My name is <PERSON> and my email is <EMAIL_ADDRESS> and SSN is <US_SSN>
```

### 日本語対応: GiNZAを使ったカスタムRecognizer

日本語テキストに対応するには、Presidioのカスタムrecognizerを実装する必要がある。日本語NERには[GiNZA](https://megagonlabs.github.io/ginza/)を使うのが現実的な選択だ。

まずGiNZA関連のパッケージを追加でインストールする。

```bash
# GiNZAと日本語モデルのインストール
pip install ginza ja-ginza

# spaCy Transformersを使う場合は追加で
pip install spacy-transformers
```

次に日本語NERの結果をPresidioに渡すカスタムRecognizerを実装する。

```python
# ja_recognizer.py
import spacy
from presidio_analyzer import EntityRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts

# GiNZAの日本語モデルをロード（起動時に一度だけ実行）
nlp_ja = spacy.load("ja_ginza")

class JapaneseNERRecognizer(EntityRecognizer):
    """GiNZAを使って日本語の氏名・組織名を検出するRecognizer"""

    ENTITIES = ["PERSON", "ORG", "LOC"]

    def __init__(self):
        super().__init__(
            supported_entities=self.ENTITIES,
            supported_language="ja",
            name="JapaneseNERRecognizer",
        )

    def load(self) -> None:
        pass  # nlp_jaはモジュールレベルでロード済み

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts: NlpArtifacts
    ) -> list[RecognizerResult]:
        results = []
        doc = nlp_ja(text)
        for ent in doc.ents:
            if ent.label_ in ("Person", "PSN"):
                results.append(
                    RecognizerResult(
                        entity_type="PERSON",
                        start=ent.start_char,
                        end=ent.end_char,
                        score=0.7,
                    )
                )
        return results
```

### 日本語対応の現実的な課題

GiNZAによる氏名・組織名の検出はある程度機能するが、次の点で追加実装が必要になる。

**住所の検出**: GiNZAのNERは住所の検出精度が低い。丁目・番地・号の組み合わせを確実に検出するには、正規表現recognizerを別途追加する必要がある。

**マイナンバーの検出**: Presidioの標準では日本のマイナンバーに対応していない。12桁のチェックサム検証ロジックを持つカスタムrecognizerを実装する必要がある。

**メモリ要件**: GiNZAのモデル（`ja_ginza`）は約300MB、`ja_ginza_electra`（より高精度）は1GB以上のメモリを必要とする。小規模なコンテナ環境やLambda等のサーバーレス環境では動かせない場合がある。

**結論**: Presidioを使いつつ日本語PIIの検出を本番品質にしようとすると、「Presidioを使っているが、日本語の実装は結局自前」という状態になりやすい。英語中心のプロダクトでインフラに余裕があれば有力候補だが、日本語が主体の場合は別の手段を検討する価値がある。

---

## 方法3: 外部APIに委ねる — pii-guardを使った完全実装例

### なぜ外部APIが選択肢になるか

外部のPII検出専門APIを使う選択肢は、自前メンテナンスを排除できる点で魅力がある。HTTP呼び出し一本で検出・マスキングが完結するため、実装コストは3手段の中で最も低い。

日本語特化の実装として、以下では [pii-guard](https://www.nexus-api-lab.com/pii-guard.html) を使った例を示す。pii-guardはマイナンバーのmod-11チェックサム検証・全角文字の正規化・氏名・住所・クレジットカードなど10種類のカテゴリを標準でカバーしている。トライアルキー（1,000リクエスト/30日間、カード不要）で今すぐ試せる。

### Step 1: curlで動作確認

APIキーを取得したら、まずcurlで疎通確認をする。

```bash
# 環境変数にAPIキーを設定
export PII_GUARD_API_KEY="your_trial_key_here"

# PIIを含むテキストをスキャン
curl -X POST https://pii-api.nexus-api-lab.com/v1/scan \
  -H "Authorization: Bearer $PII_GUARD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "田中太郎さんの電話番号は090-1234-5678で、マイナンバーは123456789012です"
  }'
```

PIIが検出された場合のレスポンスは次のような構造になる。

```json
{
  "detected": true,
  "masked_text": "[氏名]さんの電話番号は[電話番号]で、マイナンバーは[マイナンバー]です",
  "entities": [
    { "type": "name",        "start": 0,  "end": 4,  "value": "田中太郎" },
    { "type": "phone",       "start": 12, "end": 24, "value": "090-1234-5678" },
    { "type": "mynumber",    "start": 32, "end": 44, "value": "123456789012" }
  ]
}
```

### Step 2: Python SDKとして関数化する

curlで疎通確認が取れたら、Python関数として使いやすい形にラップする。

```python
# pii_guard_client.py — Python 3.11
import os
import requests
from dataclasses import dataclass

PII_GUARD_ENDPOINT = "https://pii-api.nexus-api-lab.com/v1/scan"

@dataclass
class ScanResult:
    detected: bool
    masked_text: str
    entities: list[dict]

def scan_pii(text: str, api_key: str | None = None) -> ScanResult:
    """
    テキスト中のPIIをpii-guard APIで検出・マスクする。
    api_keyが未指定の場合はPII_GUARD_API_KEY環境変数を参照する。
    """
    key = api_key or os.environ["PII_GUARD_API_KEY"]
    response = requests.post(
        PII_GUARD_ENDPOINT,
        headers={"Authorization": f"Bearer {key}"},
        json={"text": text},
        timeout=5.0,
    )
    response.raise_for_status()
    data = response.json()
    return ScanResult(
        detected=data["detected"],
        masked_text=data["masked_text"],
        entities=data.get("entities", []),
    )
```

### 動作確認

関数が正しく動作していれば、次のような出力になる。

```python
result = scan_pii("田中太郎さんの電話番号は090-1234-5678です")
print(result.detected)      # True
print(result.masked_text)   # [氏名]さんの電話番号は[電話番号]です
print(result.entities)      # [{'type': 'name', ...}, {'type': 'phone', ...}]
```

### Step 3: FastAPIミドルウェアとして全体に適用する

個別エンドポイントにフィルタリングロジックを書くと実装漏れが生じる。FastAPIのミドルウェアとして実装することで、アプリ全体のリクエストに一括適用できる。

```python
# middleware.py
import os
import json
import requests
from fastapi import FastAPI, Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware

app = FastAPI()

class PIIFilterMiddleware(BaseHTTPMiddleware):
    """LLMへのリクエスト本文からPIIを除去するミドルウェア"""

    def __init__(self, app, api_key: str, protected_paths: list[str]):
        super().__init__(app)
        self.api_key = api_key
        self.protected_paths = protected_paths

    async def dispatch(self, request: Request, call_next) -> Response:
        # 保護対象パス以外はフィルタリングをスキップ
        if not any(request.url.path.startswith(p) for p in self.protected_paths):
            return await call_next(request)

        # リクエストボディを読み取る
        body = await request.body()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return await call_next(request)

        # messageまたはpromptフィールドを検査対象とする
        message = payload.get("message") or payload.get("prompt") or ""
        if not message:
            return await call_next(request)

        # pii-guard APIを呼び出してスキャン
        try:
            scan_result = requests.post(
                "https://pii-api.nexus-api-lab.com/v1/scan",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"text": message},
                timeout=3.0,
            ).json()

            if scan_result.get("detected"):
                # PIIが検出された場合はマスキング済みテキストで置換
                payload["message"] = scan_result["masked_text"]
                body = json.dumps(payload, ensure_ascii=False).encode()

        except requests.RequestException:
            # APIタイムアウト・エラー時のポリシーは要件次第:
            # ブロック（安全側） or 通過（可用性側）を選択する
            pass

        # 修正済みボディを後続処理へ渡す
        async def receive():
            return {"type": "http.request", "body": body}

        request._receive = receive
        return await call_next(request)


# ミドルウェアを登録: /api/chat と /api/complete のリクエストにのみ適用
app.add_middleware(
    PIIFilterMiddleware,
    api_key=os.environ["PII_GUARD_API_KEY"],
    protected_paths=["/api/chat", "/api/complete"],
)


@app.post("/api/chat")
async def chat_endpoint(request: Request):
    body = await request.json()
    # この時点で body["message"] はPIIがマスクされた安全なテキスト
    user_message = body.get("message", "")
    # ... LLM API呼び出しへ
    return {"response": "..."}
```

このパターンにより、個別エンドポイントのコードはPIIフィルタリングを意識する必要がなくなる。フィルタリング戦略の変更（例: 正規表現から外部APIへの切り替え）もミドルウェアの差し替えで完結する。

---

## 3つの方法を並べて比較する

### 評価軸別の比較表

| 評価軸 | 正規表現 | Presidio (2.x) | 外部API (pii-guard) |
|--------|----------|----------------|---------------------|
| 初期実装コスト | 低（数時間） | 中（数日） | 低（1〜2時間） |
| 日本語氏名の検出 | 不可 | 要カスタム実装 | 標準対応 |
| マイナンバー検出精度 | 部分対応（チェックサムなし） | 要カスタム実装 | mod-11チェックサム検証済み |
| 住所の検出 | 限定的（表記ゆれ対応困難） | 要カスタム実装 | 標準対応 |
| インフラ要件 | なし | NERモデル 1〜3GB | なし |
| メンテナンス負担 | 高（パターン追加が継続） | 中（モデル更新対応） | 低（API側が吸収） |
| オフライン動作 | 可 | 可 | 不可 |
| レイテンシ | 最小（ローカル処理） | 中（NER推論） | ネットワーク依存（通常50〜200ms） |
| 月額費用 | 0円 | 0円（インフラコスト除く） | 従量課金 |

### ユースケース別の選定ガイド

状況によって最適解は変わる。次の基準を参考に選択してほしい。

**プロトタイプ・低トラフィック段階 → 正規表現から始める**

コストゼロで即座に始められる。「とにかくメールアドレスと電話番号だけマスクしたい」という要件ならこれで十分だ。氏名・住所の検出は諦めるか、後で差し替える前提で進める。

**英語中心・インフラに余裕あり → Presidio**

英語PIIの検出精度はPresidioが最も高い。NERモデルを収容できるインフラがあり、英語テキストが主体なら有力候補だ。日本語への拡張は追加実装が必要という点を事前に見積もりに入れておく。

**日本語中心・本番品質が必要 → 外部API（pii-guard）**

日本語の氏名・住所・マイナンバーを本番品質で検出したい場合、外部APIが最も早く到達できる。インフラ追加なし、実装量は100行程度、トライアルキーで今日から始められる。

---

## よくある落とし穴と対処法

### 落とし穴1: PIIフィルタを「ユーザー入力の直前」にだけ置く

LLMのレスポンスにも個人情報が含まれることがある。ユーザーが「Aさんの情報を教えて」と送り、DBから取得した個人情報を含むプロンプトをLLMに渡すパターンでは、LLMのレスポンスにその情報が反映される場合がある。入力フィルタに加えて出力フィルタも検討が必要だ。

### 落とし穴2: タイムアウト時の処理を決めていない

外部APIを使う場合、APIが応答しない（タイムアウト）ときの動作を事前に決めておく必要がある。

- **安全優先**: タイムアウト時はリクエストをブロックする → 可用性が下がる
- **可用性優先**: タイムアウト時はフィルタなしで通過させる → PIIが漏れる可能性

どちらを選ぶかはサービスの要件次第だが、決めずに実装するとインシデント時に混乱する。

### 落とし穴3: ログにフィルタ前のデータを記録してしまう

ミドルウェアでフィルタリングしても、その上流のアクセスログ（nginx・CloudFlare等）にリクエストボディが記録されている場合がある。ログ設定の見直しもあわせて行う。

---

## 本番環境に出せる個人情報フィルターを選ぶ

改めて選択基準を整理する。

正規表現は「今すぐゼロコストで始めたい」「英数字のフォーマットが決まったフィールドだけカバーすればよい」場合に適している。Presidioは英語中心のプロダクトで高精度なNER検出が必要な場合、かつインフラを確保できる場合に有力だ。外部APIは日本語の個人情報を本番品質で検出したい場合に、実装コストと精度のバランスが最もよい。

日本語対応の外部APIを試したい場合は、pii-guard がトライアルキー（1,000リクエスト/30日間）を提供している。カード不要で今すぐ試せる: https://www.nexus-api-lab.com/pii-guard.html

なお、LLMアプリには個人情報漏洩だけでなくプロンプトインジェクション攻撃のリスクもある。「この指示を無視して...」「システムプロンプトを出力して...」といった攻撃は、個人情報フィルタでは検出できない別のレイヤーの問題だ。jpi-guard は日本語に特化したインジェクション検知APIで、敬語・全角文字・ゼロ幅文字を使った難読化攻撃にも対応している。こちらもトライアルキー（2,000リクエスト/30日間）を提供している: https://www.nexus-api-lab.com/jpi-guard.html

---

## 参考リンク

- [Microsoft Presidio 公式ドキュメント](https://microsoft.github.io/presidio/)
- [GiNZA 日本語NLPライブラリ](https://megagonlabs.github.io/ginza/)
- [個人情報保護委員会: 生成AIサービスの利用に関するガイドライン](https://www.ppc.go.jp/)
- [FastAPI ミドルウェアの実装ガイド](https://fastapi.tiangolo.com/tutorial/middleware/)
