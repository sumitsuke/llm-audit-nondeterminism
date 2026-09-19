#!/usr/bin/env python3
"""独立検証 v2: aggregate.py を import せず、生fixturesから素朴に再計算して照合。
v1 は strict Jaccard 数セル・decoy多数決FP・1.5B行recall のみだった。
v2 (2026-07-07) は記事本文で引用する全ての数値を検算対象に拡張:
  relaxed±2 Jaccard / precision / recall / line-only recall / line drift(2 of 5) /
  ResourceLeak票の分布(26/19・同一run重複なし・45/49・6行) / SQLi 51/51 /
  decoyの eval 33票・shell=True 28票・md5 0票 / clean空run 37(72.5%)と非空ペア0.12 /
  strictキー多数決の k=26生存・k=27脱落 / 1.5Bの被弾25行/32行 / 空run数。
※対象外(集計パイプライン由来のまま): w±2/±5の多数決surface表・bootstrap CI。
"""

import json, os, csv, itertools, collections, sys

sys.stdout.reconfigure(encoding="utf-8")  # Windows の cp932 でも「—」を印字できるように（2026-09-19）

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "fixtures", "audit_logs.jsonl")
SUM = os.path.join(ROOT, "results", "m2_summary.json")
GTF = os.path.join(ROOT, "results", "gt.csv")
TGT_A = os.path.join(ROOT, "targets", "target_a.py")

cells = collections.defaultdict(list)
prov = {}
bad_lines = 0  # 2026-09-19: parse failures were silently skipped (bare except) - the very pattern this repo scans for. Count and fail.
for l in open(FIX, encoding="utf-8"):
    l = l.strip()
    if not l:
        continue
    try:
        r = json.loads(l)
    except json.JSONDecodeError:
        bad_lines += 1
        continue
    if r.get("type") == "run":
        cells[r["cell"]].append(r)
    elif r.get("type") == "provenance":
        prov[r["cell"]] = r


def issues(run):
    return (run.get("issues") or []) if run.get("schema_valid") else []


def keyset(run):
    s = set()
    for it in issues(run):
        ln = it.get("line_number")
        if ln is None:
            continue
        s.add((int(ln), str(it.get("category", "")).strip()))
    return s


# ---- 独立実装の最大二部マッチング(Kuhn) : aggregate.pyとは別実装 ----
def _match(adj, nB):
    matchB = [-1] * nB

    def try_kuhn(u, used):
        for v in adj[u]:
            if used[v]:
                continue
            used[v] = True
            if matchB[v] < 0 or try_kuhn(matchB[v], used):
                matchB[v] = u
                return True
        return False

    m = 0
    for u in range(len(adj)):
        if try_kuhn(u, [False] * nB):
            m += 1
    return m


def jac_pair(a, b, w):
    A, B = sorted(a), sorted(b)
    if not A and not B:
        return 1.0
    adj = [[j for j, (lb, cb) in enumerate(B) if cb == ca and abs(lb - la) <= w] for (la, ca) in A]
    inter = _match(adj, len(B))
    union = len(A) + len(B) - inter
    return inter / union if union else 1.0


def mean_jac(runs, w):
    ks = [keyset(r) for r in runs]
    vals = [jac_pair(ks[i], ks[j], w) for i, j in itertools.combinations(range(len(ks)), 2)]
    return sum(vals) / len(vals)


gts = collections.defaultdict(list)
for row in csv.DictReader(open(GTF, encoding="utf-8")):
    gts[row["target"]].append(
        {"gt_id": row["gt_id"], "category": row["category"], "lo": int(row["line_lo"]), "hi": int(row["line_hi"])}
    )

summ = json.load(open(SUM, encoding="utf-8"))
allok = True


def check(name, got, exp, tol=0.005):
    global allok
    ok = (exp is not None) and abs(got - exp) <= tol
    allok &= ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: independent={got:.4f} expected={exp}")
    return ok


def check_int(name, got, exp):
    global allok
    ok = got == exp
    allok &= ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: independent={got} expected={exp}")
    return ok


print("== 1) strict Jaccard (summary照合) ==")
for cell in ["d_7b_a", "d_15b_a", "d_7b_easy", "d_7b_decoy"]:
    check(f"{cell} strict Jaccard", mean_jac(cells[cell], 0), summ[cell]["jaccard"]["strict"])
for cell in ["a_15b_a", "a_7b_a", "a_15b_easy", "a_7b_easy"]:
    check(f"{cell} strict Jaccard(=1?)", mean_jac(cells[cell], 0), summ[cell]["jaccard"]["strict"])

print("== 2) relaxed ±2 Jaccard (summary照合・独立マッチング実装) ==")
check("d_7b_a Jaccard ±2", mean_jac(cells["d_7b_a"], 2), summ["d_7b_a"]["jaccard"]["relaxed2"])

print("== 3) precision / recall / line-only / drift (summary照合) ==")


def prec_recall(cell, tgt, w=2):
    g = gts[tgt]
    tot = len(g)
    precs, recs = [], []
    for r in cells[cell]:
        covered, fp = set(), 0
        for l, c in keyset(r):
            hit = None
            for gg in g:
                if gg["category"] == c and gg["lo"] - w <= l <= gg["hi"] + w:
                    hit = gg["gt_id"]
                    break
            if hit:
                covered.add(hit)
            else:
                fp += 1
        tp = len(covered)
        precs.append(tp / (tp + fp) if (tp + fp) else None)
        recs.append(tp / tot)
    pv = [p for p in precs if p is not None]
    return sum(pv) / len(pv), sum(recs) / len(recs)


def recall_lineonly(cell, tgt, w=2):
    g = gts[tgt]
    tot = len(g)
    vals = []
    for r in cells[cell]:
        cov = set()
        for ln, c in keyset(r):
            for gg in g:
                if gg["lo"] - w <= ln <= gg["hi"] + w:
                    cov.add(gg["gt_id"])
                    break
        vals.append(len(cov) / tot)
    return sum(vals) / len(vals)


p, rc = prec_recall("d_7b_a", "target_a.py")
check("d_7b_a precision", p, summ["d_7b_a"]["precision"])
check("d_7b_a recall", rc, summ["d_7b_a"]["recall"])
p15, rc15 = prec_recall("d_15b_a", "target_a.py")
check("d_15b_a recall", rc15, summ["d_15b_a"]["recall"])
check("d_15b_a recall_line_only", recall_lineonly("d_15b_a", "target_a.py"), summ["d_15b_a"]["recall_line_only"])
pe, rce = prec_recall("d_7b_easy", "target_easy.py")
check("d_7b_easy recall(cat-strict)", rce, summ["d_7b_easy"]["recall"])
check(
    "d_7b_easy recall_line_only", recall_lineonly("d_7b_easy", "target_easy.py"), summ["d_7b_easy"]["recall_line_only"]
)


# drift: 検出GT(カテゴリ+±2)のうち複数行に散ったもの
def drift(cell, tgt, w=2):
    g = gts[tgt]
    gl = collections.defaultdict(set)
    for r in cells[cell]:
        for l, c in keyset(r):
            for gg in g:
                if gg["category"] == c and gg["lo"] - w <= l <= gg["hi"] + w:
                    gl[gg["gt_id"]].add(l)
                    break
    det = list(gl)
    dr = [x for x in det if len(gl[x]) > 1]
    return len(det), len(dr)


det, dr = drift("d_7b_a", "target_a.py")
check_int("d_7b_a detected GT (article: 5)", det, 5)
check_int("d_7b_a drifted GT (article: 2 of 5 = 40%)", dr, 2)
check("d_7b_a line_drift_rate", dr / det, summ["d_7b_a"]["line_drift_rate"])

print("== 4) ResourceLeak 票の分布 (記事本文の主張) ==")
runs = cells["d_7b_a"]
N = len(runs)
v16 = v17 = both = anyrl = r1617 = 0
rl_lines = collections.Counter()
for r in runs:
    lines = {it["line_number"] for it in issues(r) if str(it.get("category", "")).strip() == "ResourceLeak"}
    if 16 in lines:
        v16 += 1
    if 17 in lines:
        v17 += 1
    if {16, 17} <= lines:
        both += 1
    if lines:
        anyrl += 1
    if {16, 17} & lines:
        r1617 += 1
    for ln in lines:
        rl_lines[ln] += 1
check_int("RL votes @line16 (26)", v16, 26)
check_int("RL votes @line17 (19)", v17, 19)
check_int("RL both lines in one run (0 -> 26+19=45 runs)", both, 0)
check_int("runs with RL @16 or 17 (45/51)", r1617, 45)
check_int("runs with RL anywhere (49/51)", anyrl, 49)
check_int("RL distinct lines (6: 12,15,16,17,18,21)", sorted(rl_lines) == [12, 15, 16, 17, 18, 21], True)

print("== 5) SQLi / decoy grey票 / md5ゼロ (記事本文の主張) ==")
sq = sum(
    1
    for r in runs
    if any(str(it.get("category", "")).strip() == "SQLInjection" and it["line_number"] == 9 for it in issues(r))
)
check_int("SQLInjection @9 (51/51)", sq, N)
druns = cells["d_7b_decoy"]
ev = sum(1 for r in druns if (15, "CodeInjection") in keyset(r))
sh = sum(1 for r in druns if (7, "CodeInjection") in keyset(r))
check_int("decoy eval() @15 CodeInjection (33/51)", ev, 33)
check_int("decoy shell=True @7 CodeInjection (28/51)", sh, 28)
md5 = sum(1 for r in druns for it in issues(r) if "md5" in str(it.get("description", "")).lower())
check_int("decoy md5-mention votes (0 — pitfall#5の裏取り)", md5, 0)

print("== 6) clean の沈黙率と非空ペア一致 (記事本文の主張) ==")
cr = cells["d_7b_clean"]
emp = sum(1 for r in cr if not keyset(r))
check_int("clean empty runs (37/51 = 72.5%)", emp, 37)
ne = [keyset(r) for r in cr if keyset(r)]
nev = [jac_pair(a, b, 0) for a, b in itertools.combinations(ne, 2)]
check("clean non-empty pairwise strict Jaccard (article: 0.12)", sum(nev) / len(nev), 0.116, tol=0.01)
check("clean unconditional strict Jaccard (summary)", mean_jac(cr, 0), summ["d_7b_clean"]["jaccard"]["strict"])

print("== 7) strictキー多数決の生存/脱落 (記事本文の主張) ==")
freq = collections.Counter()
for r in runs:
    for k in keyset(r):
        freq[k] += 1
kmaj = N // 2 + 1
check_int(
    "k=26で生存するstrictキー(GT一致)は SQLi@9 と RL@16 の2つ",
    sorted([k for k, v in freq.items() if v >= kmaj]) == [(9, "SQLInjection"), (16, "ResourceLeak")],
    True,
)
check_int("RL@16 の票数=26 (k=26で生存・k=27で脱落)", freq[(16, "ResourceLeak")], 26)
# clean w=0 k>=26 の生存キー(=FP)ゼロ
cfreq = collections.Counter()
for r in cr:
    for k in keyset(r):
        cfreq[k] += 1
check_int("clean: k=26生存キー 0 (多数決がバラバラな偽陽性を消す)", sum(1 for v in cfreq.values() if v >= kmaj), 0)
# decoy survivors(既存チェックの後継)
dfreq = collections.Counter()
for r in druns:
    for k in keyset(r):
        dfreq[k] += 1
dsurv = [k for k, v in dfreq.items() if v >= kmaj]
check_int("decoy: k=26生存キー 2 (eval/shell=True)", len(dsurv), summ["d_7b_decoy"]["surface"]["0"][kmaj - 1]["FP"])

print("== 8) 1.5Bの多弁さ / 空run (記事本文の主張) ==")
n_lines_a = len(open(TGT_A, encoding="utf-8").read().splitlines())
hit15 = set()
for r in cells["d_15b_a"]:
    for l, c in keyset(r):
        hit15.add(l)
hit15_in = {l for l in hit15 if 1 <= l <= n_lines_a}
check_int(f"1.5B hit lines on target_a ({n_lines_a}行中25行)", len(hit15_in), 25)
check_int("d_7b_a empty runs (0 — recallに空run除外バイアスなし)", sum(1 for r in runs if not keyset(r)), 0)

print("== 9) provenance整合 (seed設計の明示) ==")
check_int(
    "temp0.7セルは全て seed_mode=vary (seed=run番号0..50)",
    all(prov[c]["seed_mode"] == "vary" for c in prov if prov[c]["temp"] == 0.7),
    True,
)
check_int(
    "temp0セルは全て seed_mode=fixed",
    all(prov[c]["seed_mode"] == "fixed" for c in prov if prov[c]["temp"] == 0.0),
    True,
)

if bad_lines:
    print(
        f"  [FAIL] unparseable JSONL lines in {FIX}: {bad_lines} (every line must parse; nothing is skipped silently)"
    )
    allok = False
print("\nRESULT:", "ALL PASS" if allok else "MISMATCH FOUND")
sys.exit(0 if allok else 1)
