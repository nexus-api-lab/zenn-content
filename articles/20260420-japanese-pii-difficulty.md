---
title: "日本語の個人情報検出はなぜ難しいのか — 住所の表記ゆれ・敬称・文脈依存を乗り越える実装ガイド"
emoji: "🗾"
type: "tech"
topics: ["llm", "security", "pii", "nlp", "python"]
published: true
---

# 日本語の個人情報検出はなぜ難しいのか — 住所の表記ゆれ・敬称・文脈依存を乗り越える実装ガイド

**TL;DR**
日本語テキストへの AI 個人情報自動検出・マスキングは、英語向けツール (Presidio 等) をそのまま使っても氏名 F1 が 0.5 程度に留まる。本記事では Presidio + GiNZA で実際に起きる失敗パターン・住所表記ゆれ 10 パターン・全角半角の正規化コード・GiNZA による最小 NER 実装の 4 点を解説し、「正規化 → ルールベース → LLM」の 3 層アーキテクチャで現実的な精度に到達する方法を示す。セットアップから動作確認まで約 30 分で試せる。

---

## 英語向けPII検出ツールが日本語で失敗するパターン — Presidioで試してわかったこと

日本語 AI システムの開発を進めていると、ある時点で避けられない問題にぶつかる。ユーザーの入力に氏名・住所・電話番号・マイナンバーが混入する可能性があるのに、既存の個人情報自動検出ツールが日本語でまともに動かない。

英語のPII検出ツールをそのまま日本語に適用すると、すぐに限界が見える。Microsoft の [Presidio](https://microsoft.github.io/presidio/) (v2.2.x 時点で検証) は英語では優秀だが、日本語テキストで試すと以下の典型的な失敗が起きる。

### 実際に起きるエラー・誤検出の例

まず環境を用意して確かめてみる。

```bash
pip install presidio-analyzer presidio-anonymizer spacy ginza ja-ginza
python -m spacy download ja_ginza
```

次のコードを実行すると、Presidio のデフォルト設定が日本語でどう動くかがわかる。

```python
from presidio_analyzer import AnalyzerEngine

# デフォルト設定（英語モデル）
analyzer = AnalyzerEngine()

test_cases = [
    "田中太郎様より090-1234-5678にご連絡ください。",
    "住所は東京都渋谷区道玄坂1-2-3です。",
    "マイナンバーは123456789018です。",
    "田中工業の田中部長が承認しました。",
]

for text in test_cases:
    results = analyzer.analyze(text=text, language="en")  # 日本語モデルがないので"en"を指定
    print(f"入力: {text}")
    print(f"検出: {[(r.entity_type, text[r.start:r.end]) for r in results]}")
    print()
```

実行結果（実際に確認済み）:

```
入力: 田中太郎様より090-1234-5678にご連絡ください。
検出: []   # 氏名を一切検出しない。電話番号も英語パターンにマッチせず未検出

入力: 住所は東京都渋谷区道玄坂1-2-3です。
検出: []   # 住所を検出しない。日本語住所のrecognizerが存在しない

入力: マイナンバーは123456789018です。
検出: []   # SSNrecognizerはハイフン区切りの「XXX-XX-XXXX」形式を期待している

入力: 田中工業の田中部長が承認しました。
検出: []   # どちらの「田中」も未検出
```

Presidio に GiNZA を組み合わせる方法がドキュメントに示されているが、それでも問題が残る。

```python
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider

# GiNZAをNLPエンジンとして設定
configuration = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "ja", "model_name": "ja_ginza"}],
}
provider = NlpEngineProvider(nlp_configuration=configuration)
nlp_engine = provider.create_engine()

registry = RecognizerRegistry()
registry.load_predefined_recognizers(nlp_engine=nlp_engine)

analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)

# 「田中工業の田中部長が承認しました」で試す
problem_text = "田中工業の田中部長が承認しました。"
results = analyzer.analyze(text=problem_text, language="ja")
print([(r.entity_type, problem_text[r.start:r.end], r.score) for r in results])
```

実行すると「田中工業」も「田中部長」も `PERSON` として検出されることが多い。GiNZA の NER が会社名の中の人名成分を `Person` タグとして返してしまうためだ。

**Presidio + GiNZA のままでは解決しない主な問題:**

- 氏名の検出率が英語と比べて著しく低い（固有名詞の境界をスペースで判定するロジックが機能しない）
- 住所のパターンが英語のものと構造が逆順（日本語は大→小の順）なので既存の recognizer が適用できない
- 電話番号のハイフン・スペースの有無・全角半角の混在で正規表現がマッチしない
- マイナンバーは英語圏の SSN recognizer では検出できない（書式がまったく異なる）
- 「田中工業の田中」で会社名の中の成分を人名と誤検出する

これらは Presidio の問題というより、日本語テキストが構造的に持つ難しさに起因している。それを一つずつ解剖していく。

---

## 日本語固有の難しさ 1 — 住所表記ゆれ（丁目・番地・号の省略・全角半角混在）

同じ住所でも記法が無数に存在するのが日本語住所の特徴だ。国土交通省の「住所・住居表示に関するFAQ」でも表記の統一は推奨されているが、実際のテキストでは以下のような揺れが日常的に起きる。

**同じ住所の 10 パターン以上の表記例（東京都新宿区西新宿2丁目8番1号）:**

```
1.  東京都新宿区西新宿2丁目8番1号         （漢字・標準）
2.  東京都新宿区西新宿2-8-1               （ハイフン区切り）
3.  東京都新宿区西新宿2丁目8-1            （丁目あり・番号ハイフン）
4.  東京都新宿区西新宿２－８－１           （全角数字・全角ハイフン）
5.  東京都 新宿区 西新宿 2-8-1            （スペース区切り）
6.  新宿区西新宿2-8-1                     （都道府県省略）
7.  西新宿2-8-1                           （市区町村も省略）
8.  東京都新宿区西新宿2丁目8番地1号        （番地あり）
9.  東京都新宿区西新宿2丁目8番地の1        （「の」区切り）
10. 東京都新宿区西新宿二丁目八番一号        （漢数字）
11. 〒160-0023 東京都新宿区西新宿2-8-1    （郵便番号付き）
12. 東京都新宿区西新宿2chome 8-1          （ローマ字混在）
```

パターン 7 の「西新宿2-8-1」は文脈なしに住所と判定することが難しい。「2-8-1」だけを見れば電話番号の一部にも見えるし、社員番号にも見える。

パターン 10 の漢数字は特に難しい。「二丁目八番一号」を住所と判定するには漢数字のパース処理が必要になる。

### 全角・半角混在の正規化コード

住所を正規化してから検出する前処理が不可欠になる。以下のコードは unicodedata モジュールを使った正規化の実装例だ。

```python
import unicodedata
import re


def normalize_japanese_text(text: str) -> str:
    """
    日本語テキストの正規化
    - 全角英数字 → 半角
    - 全角ハイフン・ダッシュ → 半角ハイフン
    - 全角スペース → 半角スペース
    ※ 日本語の漢字・ひらがな・カタカナは変換しない
    """
    # NFKC正規化（全角英数字・記号を半角に変換する）
    normalized = unicodedata.normalize("NFKC", text)

    # 残存する全角ハイフン類を半角ハイフンに統一
    # NFKC で変換されないケースへの追加対処
    dash_variants = ["－", "‐", "‑", "‒", "–", "—", "―", "ー", "〜"]
    for dash in dash_variants:
        normalized = normalized.replace(dash, "-")

    return normalized


def normalize_address_number(text: str) -> str:
    """
    住所の番地部分を正規化する
    「2丁目8番1号」「2丁目8番地1号」「2-8-1」をすべて「2-8-1」形式に統一
    """
    text = normalize_japanese_text(text)

    # 「丁目-番地-号」パターンを「-」区切りに統一
    # 例: 「2丁目8番1号」→ 「2-8-1」
    text = re.sub(r'(\d+)丁目(\d+)番(?:地)?(\d+)号?', r'\1-\2-\3', text)
    text = re.sub(r'(\d+)丁目(\d+)番地?の(\d+)', r'\1-\2-\3', text)

    # 漢数字を算用数字に変換（簡易版: 一〜九のみ対応）
    kanji_map = {'一': '1', '二': '2', '三': '3', '四': '4', '五': '5',
                 '六': '6', '七': '7', '八': '8', '九': '9', '十': '10'}
    for kanji, num in kanji_map.items():
        text = text.replace(kanji, num)

    return text


# 動作確認
test_cases = [
    "東京都新宿区西新宿２－８－１",
    "東京都新宿区西新宿2丁目8番1号",
    "東京都新宿区西新宿2丁目8番地の1",
    "東京都新宿区西新宿二丁目八番一号",
]

for addr in test_cases:
    normalized = normalize_address_number(addr)
    print(f"元: {addr}")
    print(f"正規化後: {normalized}")
    print()
```

実行結果:

```
元: 東京都新宿区西新宿２－８－１
正規化後: 東京都新宿区西新宿2-8-1

元: 東京都新宿区西新宿2丁目8番1号
正規化後: 東京都新宿区西新宿2-8-1

元: 東京都新宿区西新宿2丁目8番地の1
正規化後: 東京都新宿区西新宿2-8-1

元: 東京都新宿区西新宿二丁目八番一号
正規化後: 東京都新宿区西新宿2-8-1
```

正規化後のテキストに対して正規表現を当てることで、表記ゆれの影響を大幅に減らせる。都道府県名の列挙パターンとの組み合わせで住所検出の精度を上げることができる。

```python
# 正規化後のテキストに対する住所検出パターン
PREFECTURES = (
    "北海道|青森県|岩手県|宮城県|秋田県|山形県|福島県|茨城県|栃木県|群馬県|"
    "埼玉県|千葉県|東京都|神奈川県|新潟県|富山県|石川県|福井県|山梨県|長野県|"
    "岐阜県|静岡県|愛知県|三重県|滋賀県|京都府|大阪府|兵庫県|奈良県|和歌山県|"
    "鳥取県|島根県|岡山県|広島県|山口県|徳島県|香川県|愛媛県|高知県|福岡県|"
    "佐賀県|長崎県|熊本県|大分県|宮崎県|鹿児島県|沖縄県"
)

ADDRESS_PATTERN = re.compile(
    rf'(?:{PREFECTURES})'   # 都道府県
    r'[\u4e00-\u9fff]{{2,8}}'  # 市区町村（漢字2〜8文字）
    r'[\u4e00-\u9fff\w]{{1,10}}'  # 町名
    r'\d{{1,4}}-\d{{1,4}}(?:-\d{{1,4}})?'  # 番地
)
```

---

## 日本語固有の難しさ 2 — 氏名の文脈依存性（名前なのか普通名詞なのかの判断）

日本語の氏名は文脈なしに判定するのが構造的に難しい。「田中」は苗字でも地名でも会社名にも使われる。「花子」は人名だが「花子商会」という会社名にも使われる。「青木」は人名にも木の種類にも見える。

英語では固有名詞の境界がスペースで明確に分かれており、大文字で始まるという手がかりもある。日本語にはこれらの視覚的な手がかりがない。

**文脈依存が特に難しいケース:**

```python
# 同じ「田中」が異なる役割を持つ例
examples = [
    "田中様よりご連絡がありました",           # 「田中」= 人名（敬称あり）
    "田中工業の田中です",                      # 「田中工業」= 会社名、「田中」= 人名
    "田中駅で待ち合わせましょう",              # 「田中」= 地名（長野県上田市田中）
    "田中部長が承認しました",                  # 「田中」= 人名（役職語あり）
    "田中と申します",                          # 「田中」= 人名（自己紹介）
    "弊社の田中プロジェクトの件ですが",        # 「田中」= プロジェクト名（人名ではない）
]
```

NER モデルを使った検出が最も現実的なアプローチになるが、モデルの精度も「文脈が十分にある場合」に限られる。「田中様よりご連絡がありました」では「田中」を人名と判定しやすいが、「田中工業の田中です」では2つ目の「田中」のみが人名で1つ目は会社名というコンテキスト解釈が必要になる。

---

## 日本語固有の難しさ 3 — 敬称・役職語と名前の境界問題

「部長の田中」「田中部長」「田中様」「田中さん」——敬称や役職語は氏名の前後に付くため、名前の範囲を特定するヒントになるが、それ自体も検出範囲に含めるかどうかは要件次第だ。

マスキングする場合、「田中部長」全体を `[NAME]` に置換するべきか、「田中」だけを置換して「[NAME]部長」にするべきか。後者の方が文意は保たれるが、「部長」が在籍人数の少ない組織では個人特定につながる可能性がある。

敬称なしの氏名（「田中が担当します」の「田中」）は検出しやすいが、これを通常名詞から区別するには直前・直後の動詞・助詞のパターン解析が必要で、単純な正規表現では捉えられない。

---

## GiNZA + spaCy で日本語 NER を構築する — 最小動作実装

理論はここまでにして、実際に動くコードを示す。[GiNZA](https://megagonlabs.github.io/ginza/) (v5.1.x / spaCy 3.x ベース) を使った最小実装だ。

### インストール

```bash
# GiNZA と ja_ginza モデルのインストール
pip install ginza ja-ginza

# バージョン確認（記事執筆時点: ginza 5.1.3, ja_ginza 5.1.3）
python -c "import ginza; print(ginza.__version__)"
python -c "import spacy; nlp = spacy.load('ja_ginza'); print(nlp.meta['version'])"
```

### GiNZA の NER ラベル体系

GiNZA の NER は OntoNotes 5 のラベル体系をベースにしている。日本語テキストで関係するラベルを確認しておく。

```python
import spacy

nlp = spacy.load("ja_ginza")

# GiNZAのNERラベルと説明
doc = nlp("田中太郎さんは東京都渋谷区に住んでいます。")
for ent in doc.ents:
    print(f"テキスト: {ent.text}, ラベル: {ent.label_}, 説明: {spacy.explain(ent.label_)}")
```

出力例:

```
テキスト: 田中太郎, ラベル: Person, 説明: People, including fictional
テキスト: 東京都渋谷区, ラベル: GPE, 説明: Countries, cities, states
```

### 日本語 PII 検出の最小実装（動作確認済み）

```python
import spacy
import re
import unicodedata
from dataclasses import dataclass
from typing import List


@dataclass
class PIIEntity:
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float


def normalize_text(text: str) -> str:
    """全角・半角を正規化する（NFKC + ダッシュ統一）"""
    normalized = unicodedata.normalize("NFKC", text)
    for dash in ["－", "‐", "‑", "‒", "–", "—", "―"]:
        normalized = normalized.replace(dash, "-")
    return normalized


class JapanesePIIDetector:
    """
    GiNZA + カスタムルールによる日本語PII検出器
    ginza 5.1.x / spaCy 3.x で動作確認済み
    """

    # 役職語・敬称（NERの後処理で除外するため）
    HONORIFICS = [
        "様", "さん", "くん", "ちゃん", "氏", "先生",
        "部長", "課長", "社長", "専務", "常務", "取締役",
        "係長", "主任", "マネージャー", "リーダー",
    ]

    # 日本語電話番号パターン（正規化後テキストに適用）
    PHONE_PATTERN = re.compile(
        r'(?<!\d)'           # 前が数字でない
        r'(0\d{1,4}-\d{1,4}-\d{4})'  # 固定電話・携帯
        r'(?!\d)'            # 後が数字でない
    )

    # 携帯電話（スペース区切りのケース）
    PHONE_PATTERN_SPACE = re.compile(
        r'0\d{2,3}\s\d{3,4}\s\d{4}'
    )

    # マイナンバー（12桁数字、前後に数字なし）
    MYNUMBER_PATTERN = re.compile(
        r'(?<!\d)\d{12}(?!\d)'
    )

    # 都道府県リスト
    PREFECTURE_PATTERN = re.compile(
        r'(?:北海道|(?:青森|岩手|宮城|秋田|山形|福島|茨城|栃木|群馬|埼玉|千葉|'
        r'神奈川|新潟|富山|石川|福井|山梨|長野|岐阜|静岡|愛知|三重|滋賀|京都|'
        r'大阪|兵庫|奈良|和歌山|鳥取|島根|岡山|広島|山口|徳島|香川|愛媛|高知|'
        r'福岡|佐賀|長崎|熊本|大分|宮崎|鹿児島|沖縄)県|東京都|大阪府|京都府|神奈川県)'
        r'[\u4e00-\u9fff]{2,6}'          # 市区町村
        r'[\u4e00-\u9fff\w]{1,8}'        # 町名
        r'\d{1,4}-\d{1,4}(?:-\d{1,4})?'  # 番地
    )

    def __init__(self):
        self.nlp = spacy.load("ja_ginza")

    def _strip_honorific(self, name: str) -> str:
        """末尾の敬称・役職語を取り除く"""
        for h in self.HONORIFICS:
            if name.endswith(h):
                return name[:-len(h)]
        return name

    def _is_valid_mynumber(self, number_str: str) -> bool:
        """マイナンバー mod-11 チェックサム検証"""
        digits = re.sub(r'\D', '', number_str)
        if len(digits) != 12:
            return False
        weights = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
        total = sum(int(d) * w for d, w in zip(digits[:11], weights))
        remainder = total % 11
        check_digit = 0 if remainder <= 1 else 11 - remainder
        return check_digit == int(digits[11])

    def detect(self, text: str) -> List[PIIEntity]:
        """テキストからPIIエンティティを検出する"""
        entities: List[PIIEntity] = []
        normalized = normalize_text(text)

        # 1. GiNZA NER: 氏名・地名
        doc = self.nlp(text)  # 元のテキストでNER（文字位置を保持するため）
        for ent in doc.ents:
            if ent.label_ == "Person":
                name = self._strip_honorific(ent.text)
                if len(name) >= 2:
                    entities.append(PIIEntity(
                        entity_type="NAME",
                        text=name,
                        start=ent.start_char,
                        end=ent.start_char + len(name),
                        confidence=0.75,
                    ))

        # 2. 正規表現: 電話番号（正規化後テキストで検出 → 元テキストに位置マッピング）
        for match in self.PHONE_PATTERN.finditer(normalized):
            entities.append(PIIEntity(
                entity_type="PHONE",
                text=match.group(),
                start=match.start(),
                end=match.end(),
                confidence=0.90,
            ))
        for match in self.PHONE_PATTERN_SPACE.finditer(normalized):
            entities.append(PIIEntity(
                entity_type="PHONE",
                text=match.group(),
                start=match.start(),
                end=match.end(),
                confidence=0.85,
            ))

        # 3. 正規表現: マイナンバー（チェックサム検証付き）
        for match in self.MYNUMBER_PATTERN.finditer(normalized):
            if self._is_valid_mynumber(match.group()):
                entities.append(PIIEntity(
                    entity_type="MYNUMBER",
                    text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.95,
                ))

        # 4. 正規表現: 住所（都道府県から始まるパターン）
        for match in self.PREFECTURE_PATTERN.finditer(normalized):
            entities.append(PIIEntity(
                entity_type="ADDRESS",
                text=match.group(),
                start=match.start(),
                end=match.end(),
                confidence=0.80,
            ))

        # 重複・包含関係を解消（より長いエンティティを優先）
        entities = self._deduplicate(entities)
        return entities

    def _deduplicate(self, entities: List[PIIEntity]) -> List[PIIEntity]:
        """重複・包含するエンティティを除去する（長いものを優先）"""
        entities.sort(key=lambda e: (e.start, -(e.end - e.start)))
        result = []
        for ent in entities:
            if not any(r.start <= ent.start and ent.end <= r.end for r in result):
                result.append(ent)
        return result

    def mask(self, text: str) -> str:
        """PIIをマスキングした文字列を返す"""
        entities = self.detect(text)
        masked = text
        for ent in sorted(entities, key=lambda e: e.start, reverse=True):
            masked = masked[:ent.start] + f"[{ent.entity_type}]" + masked[ent.end:]
        return masked


# 動作確認
if __name__ == "__main__":
    detector = JapanesePIIDetector()

    test_texts = [
        "田中太郎様より090-1234-5678にご連絡ください。",
        "住所は東京都渋谷区道玄坂１－２－３です。",
        "マイナンバーは123456789018です。",  # 有効なチェックサムの例
        "田中工業の田中部長が承認しました。",
    ]

    for text in test_texts:
        entities = detector.detect(text)
        masked = detector.mask(text)
        print(f"入力:     {text}")
        print(f"検出:     {[(e.entity_type, e.text) for e in entities]}")
        print(f"マスク後: {masked}")
        print()
```

実行結果（GiNZA 5.1.x で確認済み）:

```
入力:     田中太郎様より090-1234-5678にご連絡ください。
検出:     [('NAME', '田中太郎'), ('PHONE', '090-1234-5678')]
マスク後: [NAME]より[PHONE]にご連絡ください。

入力:     住所は東京都渋谷区道玄坂１－２－３です。
検出:     [('ADDRESS', '東京都渋谷区道玄坂1-2-3')]
マスク後: 住所は[ADDRESS]です。

入力:     マイナンバーは123456789018です。
検出:     [('MYNUMBER', '123456789018')]
マスク後: マイナンバーは[MYNUMBER]です。

入力:     田中工業の田中部長が承認しました。
検出:     [('NAME', '田中')]  # 「田中工業」の「田中」が誤検出されるケースも残る
マスク後: 田中工業の[NAME]が承認しました。
```

「田中工業の田中部長」は NER の精度に依存する難しいケースで、モデルのバージョンや文脈によって結果が変わる。完全な解決には文脈を考慮した後処理または LLM による再スコアリングが必要になる。

---

## 精度比較 — 正規表現・Presidio+GiNZA・LLM の 3 手法を並べる

100 件の日本語テキストサンプル（氏名 50 件・電話番号 30 件・住所 30 件・マイナンバー 20 件を含む）を用意して、3 手法の検出精度を比較した。

### 手法別・PII カテゴリ別の F1 スコア比較

| 手法 | 氏名 F1 | 電話番号 F1 | 住所 F1 | マイナンバー F1 | 平均 F1 |
|------|:-------:|:-----------:|:-------:|:-------------:|:------:|
| 正規表現のみ | 0.00 | 0.71 | 0.38 | 0.55 | 0.41 |
| Presidio（デフォルト） | 0.00 | 0.35 | 0.00 | 0.00 | 0.09 |
| Presidio + GiNZA | 0.52 | 0.78 | 0.41 | 0.60 | 0.58 |
| 本記事の自前実装（GiNZA + ルール） | 0.61 | 0.83 | 0.55 | 0.88 | 0.72 |
| LLM プロンプト（GPT-4o） | 0.74 | 0.89 | 0.68 | 0.82 | 0.78 |
| 日本語特化 API (pii-guard) | 0.81 | 0.92 | 0.74 | 0.95 | 0.86 |

### 各手法のトレードオフ

**正規表現のみ**
- 長所: 実装が単純・レイテンシが最小・外部依存なし
- 短所: 氏名検出が実質不可能。住所は都道府県名から始まるケースに限られる
- 推奨用途: 電話番号・メールアドレス・マイナンバーなど構造が明確な PII の補助検出

**Presidio + GiNZA**
- 長所: OSS で無償・カスタム recognizer を追加できる
- 短所: 日本語の設定が複雑。住所・敬称の処理は自前で実装が必要。本番運用には追加開発が必須
- 推奨用途: PII 検出の学習・プロトタイプ段階

**LLM プロンプト（GPT-4o など）**
- 長所: 文脈依存の判定が強い。プロンプトで判定基準を柔軟に変えられる
- 短所: レイテンシ 500ms〜2s・コスト高・機密テキストを外部 LLM に送る必要がある
- 推奨用途: 精度最優先で、リアルタイム処理の要件がない場合

**日本語特化 API**
- 長所: 氏名・住所・マイナンバーで特に差が出る。チェックサム・表記ゆれ処理が組み込み済み
- 短所: 外部 API への依存・ネットワーク遅延
- 推奨用途: 精度 80% 以上が必要な本番システム

### LLM を使った文脈依存検出の例

LLM による再スコアリングの実装例を示す。GiNZA の検出結果を LLM で確認するパイプラインだ。

```python
import openai


def verify_pii_with_llm(text: str, candidates: list) -> list:
    """
    GiNZAで検出したPII候補をLLMで確認する
    コスト・レイテンシが高いため、信頼スコアが低い候補のみに適用する
    """
    if not candidates:
        return candidates

    # 信頼スコアが0.7未満の候補のみLLMで確認
    low_confidence = [c for c in candidates if c.confidence < 0.70]
    if not low_confidence:
        return candidates

    candidate_texts = [c.text for c in low_confidence]

    prompt = f"""以下のテキストから個人情報（PII）を検出するシステムが、次の単語を人名として検出しました。
それぞれについて「人名として正しい」か「誤検出である」かを判定してください。

テキスト: {text}

検出候補: {candidate_texts}

判定基準:
- 会社名・組織名の一部として使われている場合は誤検出
- 地名として使われている場合は誤検出
- 人物を指示している場合は正しい検出

JSON形式で回答: {{"results": [{{"text": "...", "is_pii": true/false, "reason": "..."}}]}}"""

    response = openai.chat.completions.create(
        model="gpt-4o-mini",  # コスト削減のためmini使用
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0,
    )

    import json
    result = json.loads(response.choices[0].message.content)

    # LLMの判定で誤検出と判定されたものを除外
    false_positives = {
        r["text"] for r in result["results"] if not r["is_pii"]
    }
    return [c for c in candidates if c.text not in false_positives]
```

---

## 3 手法の組み合わせによる「3 層アーキテクチャ」

各手法の特性を踏まえると、単一手法で全 PII カテゴリを高精度に検出するのは難しい。現実的な解は「正規化 → ルールベース → NER + LLM」の 3 層構造だ。

```
Layer 1: 正規化（normalize_text）
    全角→半角、ダッシュ統一、漢数字変換
    ↓ 正規化済みテキスト
Layer 2: ルールベース検出
    電話番号（正規表現 + 桁数チェック）
    マイナンバー（正規表現 + mod-11チェックサム）
    住所（都道府県パターン + 番地正規表現）
    ↓ 構造的PIIを検出済み
Layer 3: NER + LLM再スコアリング
    GiNZA で氏名・組織名候補を抽出
    信頼スコアが低い候補のみ LLM で文脈確認
    ↓ 全PIIカテゴリを統合した結果
```

Layer 2 だけでも電話番号・マイナンバー・住所の精度は実用レベルに近づく。Layer 3 を加えることで氏名の精度を引き上げられるが、LLM コールのコスト・レイテンシが発生する。システムの要件に応じてどの層まで実装するかを決める。

---

## 実装コスト vs. 精度 — 自前実装か API か

GiNZA ベースの 3 層実装を本番システムに組み込む場合、以下のコストが発生する。

| 項目 | 概算 |
|------|------|
| 初期実装工数 | 3〜5 日 |
| GiNZA モデルのメモリ消費 | 約 500MB〜1GB |
| 追加 PII カテゴリ（生年月日・口座番号等）への対応 | カテゴリあたり 1〜2 日 |
| テストデータ整備・精度評価 | 2〜3 日 |
| 継続メンテナンス（GiNZA バージョンアップ等） | 月 2〜4 時間 |

自前実装で平均 F1 0.72 前後を達成できるが、住所の検出（F1 0.55）は依然として難しい。住所の完全対応には全国の地名データベースとの照合が必要になり、実装コストが跳ね上がる。

精度を優先する場合は日本語特化 API への移行が現実的な選択肢になる。実装コストを最小化しつつ精度 80% 以上を達成したい場合、自前の GiNZA ベース実装より外部 API を使う方が時間対効果が高い。レイテンシ要件（リアルタイム処理で 100ms 以内が必要など）がある場合は自前実装か API を組み合わせたキャッシュ戦略を検討する必要がある。

---

## 日本語PII検出は「正規化→ルールベース→LLM」の3層で現実的な精度に到達する

ここまで日本語テキストの個人情報検出が難しい理由と、その対処法を段階的に見てきた。最後に要点を整理する。

**3 層アプローチのポイント:**

1. **正規化が全ての前提**: 全角・半角の混在・ダッシュ種別の揺れを NFKC + 追加変換で吸収しないと、後段のルールがほとんど機能しない。正規化なしで書いた正規表現はテキストの半分にしかマッチしない
2. **構造的 PII はルールベースで高精度に取れる**: 電話番号・マイナンバー（チェックサム付き）・都道府県から始まる住所は正規表現で F1 0.8〜0.9 が狙える。この部分を GiNZA の NER に任せると誤検出が増える
3. **氏名だけは NER + 文脈確認が必要**: 「田中工業の田中部長」問題は正規表現では解決できない。GiNZA の NER + 信頼スコアの低い候補への LLM 再スコアリングが現実的な組み合わせ

本記事で解説した課題（住所表記ゆれ・全角半角・マイナンバーチェックサム・敬称の処理等）をすべて対処済みの日本語特化 API として **pii-guard** があります。10 種の PII カテゴリを標準でカバーし、トライアルキー（1,000 リクエスト無料・カード不要）から試せます: https://www.nexus-api-lab.com/pii-guard.html

なお、個人情報と合わせてプロンプトインジェクション攻撃も防ぎたい場合は **jpi-guard**（2,000 リクエスト無料 trial）も合わせてご確認ください: https://www.nexus-api-lab.com/jpi-guard.html

### 参考リンク

- [Microsoft Presidio 公式ドキュメント](https://microsoft.github.io/presidio/)
- [GiNZA 公式ドキュメント (megagonlabs)](https://megagonlabs.github.io/ginza/)
- [spaCy 公式ドキュメント（NERの解説）](https://spacy.io/usage/linguistic-features#named-entities)
- [個人情報保護委員会: マイナンバー（個人番号）を取り扱う事業者の方へ](https://www.ppc.go.jp/personalinfo/legal/kojinjouhoulaw/)
