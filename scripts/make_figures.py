#!/usr/bin/env python3
"""make_figures.py — 主峰の図。7B temp0.7 の各指摘が51回中何回出たか＝票数。
多数決線(26)を跨ぐ様子で "stickiness ⊥ truth" を一枚に。凍結fixturesから再生成＝決定的。"""

import json, collections, os
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "fixtures", "audit_logs.jsonl")
OUT = os.path.join(ROOT, "figures", "nofreelunch.png")
os.makedirs(os.path.dirname(OUT), exist_ok=True)


def freq(cell):
    f = collections.Counter()
    n = 0
    for l in open(FIX, encoding="utf-8"):
        r = json.loads(l)
        if r.get("type") == "run" and r["cell"] == cell:
            n += 1
            for it in r.get("issues") or []:
                f[(it.get("line_number"), str(it.get("category")).strip())] += 1
    return f, n


fa, N = freq("d_7b_a")
fd, _ = freq("d_7b_decoy")

# (label, count, kind)  kind: "true"=真の欠陥 / "smell"=灰色スメル(GT外)
items = [
    ("SQLi @L9\n(true bug)", fa[(9, "SQLInjection")], "true"),
    ("ResourceLeak @L16\n(true, drifts)", fa[(16, "ResourceLeak")], "true"),
    ("ResourceLeak @L17\n(true, other line)", fa[(17, "ResourceLeak")], "true"),
    ("eval() @L15\n(context smell)", fd[(15, "CodeInjection")], "smell"),
    ("shell=True @L7\n(context smell)", fd[(7, "CodeInjection")], "smell"),
]
labels = [x[0] for x in items]
counts = [x[1] for x in items]
colors = ["#2166ac" if x[2] == "true" else "#b2182b" for x in items]

fig, ax = plt.subplots(figsize=(9, 4.6))
bars = ax.bar(range(len(items)), counts, color=colors, width=0.62)
maj = N // 2 + 1
ax.axhline(maj, ls="--", lw=1.6, color="black")
ax.text(len(items) - 0.5, maj + 0.6, f"majority threshold = {maj}/{N}", ha="right", va="bottom", fontsize=10)
ax.set_ylim(0, N + 2)
ax.set_ylabel(f"runs that flagged it (of {N})")
ax.set_xticks(range(len(items)))
ax.set_xticklabels(labels, fontsize=9)
ax.set_title(
    "Majority voting selects for stickiness, not truth\n(Qwen2.5-Coder 7B, temp=0.7, N=51, key = line+category)",
    fontsize=11,
)
for b, c in zip(bars, counts):
    ax.text(b.get_x() + b.get_width() / 2, c + 0.5, str(c), ha="center", va="bottom", fontsize=9)
# 凡例
from matplotlib.patches import Patch

ax.legend(
    handles=[
        Patch(color="#2166ac", label="true defect (in ground truth)"),
        Patch(color="#b2182b", label="context-dependent smell (not in GT)"),
    ],
    loc="upper center",
    fontsize=9,
    framealpha=0.9,
)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout()
plt.savefig(OUT, dpi=130)
print("wrote", OUT, "| counts:", dict(zip([l.split(chr(10))[0] for l in labels], counts)), "majority=", maj)
