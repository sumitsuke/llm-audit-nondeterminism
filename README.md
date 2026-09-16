# llm-audit-nondeterminism

同じコードをローカルLLM（Qwen2.5-Coder 1.5B/7B・Ollama）に **N回監査させたとき、指摘（`(行番号, カテゴリ)`）がどれだけ一致するか** を実測した再現キット。
記事：**[同じコードをローカルLLMに51回監査させたら：多数決は"正しさ"より"しつこさ"を選んでいた](https://zenn.dev/tauridev/articles/llm-audit-nondeterminism)**（Zenn）。

## 二層再現（この設計が肝）

- **第1層（生成・非決定・要 Ollama）**：LLM監査の生ログ。著者が1回だけ実行し `fixtures/audit_logs.jsonl` に**凍結**。読者が自分で回すと別の分布になる＝それが論点。
- **第2層（集計・決定的・LLM不要）**：凍結ログを読んで数表を再生成。**誰が回しても同じ**。

## 再現手順

```bash
# 第2層（決定的・LLM不要）：凍結ログから数表を再生成
python scripts/aggregate.py            # -> results/m2_summary.json

# 独立再計算：集計コードを経由せず生ログから主要数値を検算し一致を確認（ALL PASS になる）
python scripts/verify_independent.py

# 図の再生成
python scripts/make_figures.py         # -> figures/nofreelunch.png

# （任意・第1層）自分で生成し直す：要 Ollama + Qwen2.5-Coder。凍結ログは .prev に退避される
#   OLLAMA_EXE=/path/to/ollama bash scripts/run_m2.sh
# seed 不活性の確認（temp0 で seed を変えても出力が変わらないこと）
#   python scripts/seed_probe.py        # -> results/seed_probe.txt
```

Windows は `PYTHONUTF8=1` を推奨。

## 構成

```
targets/     監査対象コード（欠陥入り target_a / clean / decoy / easy）
results/gt.csv   グラウンドトゥルース（欠陥の 行×種別・事前登録）
scripts/     audit_run(生成) aggregate(集計) verify_independent(独立検算) make_figures seed_probe run_m2
fixtures/    audit_logs.jsonl（N回監査の生ログ・凍結／provenance付き）
results/     m2_summary.json（数表）・seed_probe.txt など
figures/     nofreelunch.png
```

## ライセンス

コード：MIT。データ（fixtures/ results/ targets/ gt.csv）：CC0。
第三者：Qwen2.5-Coder（Apache-2.0）、Ollama（MIT）。詳細は [LICENSE](LICENSE)。

## 設計・検証の記録（Sumitsuke Lab）

このリポジトリの背景・検証環境・判定・最終検証日・失敗例は、Sumitsuke Lab の本家記事にまとめています。

- 同じコードを LLM に 51 回監査させると指摘は再現するのか——温度 0／0.7 の一致率と多数決の落とし穴 → https://sumitsuke.jp/lab/llm-audit-51-runs/
- 受託（生成 AI コード・外注コードの点検と修理・テキスト完結） → https://sumitsuke.jp/works/repair/

## 利益相反（COI）と連絡先

筆者（**tauridev**）は AIコード検証・監査サービスの出品者で、本リポの結論「多数決は"正しさ"より"しつこさ"を選ぶ／最後は人が裁定する」は事業上の立場に有利になり得ます。だからこそ生成ログ（`fixtures/`）・集計コード・独立検算（`verify_independent.py`）・事前登録のグラウンドトゥルース（`gt.csv`）まで公開し、読者が自分で検証できるようにしています。

- AIで作ったアプリの検証・監査・修正 → https://coconala.com/services/4282365
- プロフィール → https://coconala.com/users/6153961 ／ https://getaxiom.dev
