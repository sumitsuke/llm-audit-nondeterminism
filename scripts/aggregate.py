#!/usr/bin/env python3
"""
aggregate.py v2 — 第2層(決定的・集計)。監査3体の指摘を反映:
  - relaxed-Jaccard は最適二部マッチング(対称)・run内は dedup
  - precision は空run除外・total_gt=0 は None
  - 多数決クラスタは1クラスタが複数gt_idを信用可(単リンク併合の過少計上を修正)
  - cp932回避(stdout utf-8)・ライブfixtureの末尾切れskip・N=0/偶数Nガード
  - 不確実性: run単位bootstrap 95%CI(seed固定=決定的)。検出率にも同bootstrap。
信頼性(Jaccard,GTフリー) と 妥当性(precision/recall/FP,GT) を配線分離。stdlibのみ。
"""

import json, os, csv, argparse, random, sys
from collections import defaultdict

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXT = os.path.join(ROOT, "fixtures", "audit_logs.jsonl")
GT = os.path.join(ROOT, "results", "gt.csv")
BOOT_B = 1000
BOOT_SEED = 12345


def load_gt():
    gts = defaultdict(list)
    if not os.path.exists(GT):
        return gts
    with open(GT, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gts[row["target"]].append(
                {
                    "gt_id": row["gt_id"],
                    "category": row["category"],
                    "lo": int(row["line_lo"]),
                    "hi": int(row["line_hi"]),
                }
            )
    return gts


def load_cells(path):
    cells = defaultdict(lambda: {"prov": None, "runs": []})
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)  # ライブfixtureの末尾切れをskip
            except json.JSONDecodeError:
                continue
            c = rec.get("cell")
            if rec.get("type") == "provenance":
                cells[c]["prov"] = rec
            elif rec.get("type") == "run":
                cells[c]["runs"].append(rec)
    return cells


def run_keyset(run):
    ks = set()
    if run.get("schema_valid") and run.get("issues"):
        for it in run["issues"]:
            ln, cat = it.get("line_number"), str(it.get("category", "")).strip()
            if ln is None:
                continue
            try:
                ks.add((int(ln), cat))
            except (ValueError, TypeError):
                continue
    return ks  # set = run内 dedup


def _max_matching(adj, nR):
    matchR = [-1] * nR

    def aug(u, seen):
        for v in adj[u]:
            if not seen[v]:
                seen[v] = True
                if matchR[v] == -1 or aug(matchR[v], seen):
                    matchR[v] = u
                    return True
        return False

    res = 0
    for u in range(len(adj)):
        if aug(u, [False] * nR):
            res += 1
    return res


def jaccard(a, b, w):
    """a,b: set of (line,cat)。同category・|Δline|<=w を最適二部マッチ(対称)。GTフリー。"""
    A, B = list(a), list(b)
    if not A and not B:
        return 1.0
    adj = [[j for j, (lb, cb) in enumerate(B) if cb == ca and abs(lb - la) <= w] for (la, ca) in A]
    inter = _max_matching(adj, len(B))
    union = len(A) + len(B) - inter
    return inter / union if union else 1.0


def pairwise_matrix(keysets, w):
    N = len(keysets)
    M = [[1.0] * N for _ in range(N)]
    for i in range(N):
        for j in range(i + 1, N):
            v = jaccard(keysets[i], keysets[j], w)
            M[i][j] = M[j][i] = v
    return M


def mean_offdiag(M, idx):
    s = c = 0.0
    for a in range(len(idx)):
        for b in range(a + 1, len(idx)):
            if idx[a] == idx[b]:  # bootstrapで同一runを2回引いた自己ペア(J=1)を除外＝CI上振れバグ修正
                continue  # 点推定(idx=range(N)・全て相異)には影響しない
            s += M[idx[a]][idx[b]]
            c += 1
    return s / c if c else 1.0


def boot_ci_matrix(M, N, rng, B=BOOT_B):
    if N < 2:
        return (1.0, 1.0)
    vals = []
    for _ in range(B):
        idx = [rng.randrange(N) for _ in range(N)]
        vals.append(mean_offdiag(M, idx))
    vals.sort()
    return (round(vals[int(0.025 * B)], 3), round(vals[int(0.975 * B)], 3))


def boot_ci_vals(values, rng, B=BOOT_B):
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return (None, None)
    out = []
    n = len(vals)
    for _ in range(B):
        s = sum(vals[rng.randrange(n)] for _ in range(n)) / n
        out.append(s)
    out.sort()
    return (round(out[int(0.025 * B)], 3), round(out[int(0.975 * B)], 3))


def cluster_lines(lines_sorted, w):
    clusters, cur = [], [lines_sorted[0]]
    for ln in lines_sorted[1:]:
        if ln - cur[-1] <= w:
            cur.append(ln)
        else:
            clusters.append(cur)
            cur = [ln]  # 新リスト(参照バグ回避)。旧一行版は cur.clear() で破壊していた
    clusters.append(cur)
    return clusters


def build_clusters(runs_keysets, w):
    cat_line_runs = defaultdict(lambda: defaultdict(set))
    for rid, ks in enumerate(runs_keysets):
        for l, c in ks:
            cat_line_runs[c][l].add(rid)
    clusters = []
    for c, line_runs in cat_line_runs.items():
        for cl in cluster_lines(sorted(line_runs.keys()), w):
            runs_cov = set()
            for l in cl:
                runs_cov |= line_runs[l]
            clusters.append({"cat": c, "lines": list(cl), "freq": len(runs_cov)})
    return clusters


def cluster_gt_ids(cluster, gts, w):
    ids = set()
    for g in gts:
        if g["category"] == cluster["cat"] and any(g["lo"] - w <= l <= g["hi"] + w for l in cluster["lines"]):
            ids.add(g["gt_id"])
    return ids


def match_finding_gt(l, c, gts, w):
    for g in gts:
        if g["category"] == c and g["lo"] - w <= l <= g["hi"] + w:
            return g["gt_id"]
    return None


def match_finding_gt_line(l, gts, w):
    """category不問・行のみ一致。"位置は当てたがカテゴリ違い" を分離するため。"""
    for g in gts:
        if g["lo"] - w <= l <= g["hi"] + w:
            return g["gt_id"]
    return None


def analyze_cell(cell, gts, wins=(0, 2, 5), val_w=2):
    runs = cell["runs"]
    N = len(runs)
    if N == 0:
        return None
    keysets = [run_keyset(r) for r in runs]
    schema_ok = sum(1 for r in runs if r.get("schema_valid"))
    empty = sum(1 for ks in keysets if not ks)
    total_gt = len(gts)
    rng = random.Random(BOOT_SEED)

    # 信頼性(GTフリー)
    jac, jac_ci = {}, {}
    for w in (0, 2, 5):
        M = pairwise_matrix(keysets, w)
        name = "strict" if w == 0 else f"relaxed{w}"
        jac[name] = round(mean_offdiag(M, list(range(N))), 3)
        jac_ci[name] = boot_ci_matrix(M, N, rng)

    # 妥当性(per-run, val_w): precision は空run除外・recall は全run
    precs, recs, fps = [], [], []
    for ks in keysets:
        covered, fp = set(), 0
        for l, c in ks:
            gid = match_finding_gt(l, c, gts, val_w)
            if gid:
                covered.add(gid)
            else:
                fp += 1
        tp = len(covered)
        precs.append(tp / (tp + fp) if (tp + fp) else None)  # 空run=None(除外)
        recs.append(tp / total_gt if total_gt else None)
        fps.append(fp)
    prec_vals = [p for p in precs if p is not None]
    # total_gt=0(clean/decoy)は precision 未定義 → None（recallと整合・JSONに0.0を残さない）
    precision = round(sum(prec_vals) / len(prec_vals), 3) if (prec_vals and total_gt) else None
    recall = round(sum(recs) / N, 3) if total_gt else None
    fp_per_run = round(sum(fps) / N, 2)

    # line-only recall(category不問): 低recallが"位置未検出"か"カテゴリ違い"かを分離
    line_recs, detected_line = [], set()
    for ks in keysets:
        cov = set()
        for l, c in ks:
            gid = match_finding_gt_line(l, gts, val_w)
            if gid:
                cov.add(gid)
                detected_line.add(gid)
        line_recs.append(len(cov) / total_gt if total_gt else None)
    recall_line_only = round(sum(line_recs) / N, 3) if total_gt else None

    # line_drift(val_w): 検出gt のうち検出行が複数に散る割合 + 窓外脱落は別掲
    gt_lines = defaultdict(set)
    for ks in keysets:
        for l, c in ks:
            gid = match_finding_gt(l, c, gts, val_w)
            if gid:
                gt_lines[gid].add(l)
    detected = list(gt_lines.keys())
    drift = [g for g in detected if len(gt_lines[g]) > 1]
    drift_rate = round(len(drift) / len(detected), 3) if detected else None

    # 多数決 no-free-lunch: w × k（クラスタは複数gt_id信用可）
    surface = {}
    for w in wins:
        clusters = build_clusters(keysets, w)
        for cl in clusters:
            cl["gt"] = cluster_gt_ids(cl, gts, w)
        pts = []
        for k in range(1, N + 1):
            adopted = [cl for cl in clusters if cl["freq"] >= k]
            covered = set()
            for cl in adopted:
                covered |= cl["gt"]
            fp = sum(1 for cl in adopted if not cl["gt"])
            tp = len(covered)
            pts.append({"k": k, "tau": round(k / N, 3), "TP": tp, "FP": fp, "FN": total_gt - tp})
        surface[w] = pts

    return {
        "N": N,
        "N_odd": bool(N % 2),
        "schema_valid_rate": round(schema_ok / N, 3),
        "empty_rate": round(empty / N, 3),
        "mean_issues": round(sum(len(k) for k in keysets) / N, 2),
        "jaccard": jac,
        "jaccard_ci95": jac_ci,
        "precision": precision,
        "precision_ci95": boot_ci_vals(precs, rng),
        "recall": recall,
        "recall_ci95": (boot_ci_vals(recs, rng) if total_gt else (None, None)),
        "fp_per_run": fp_per_run,
        "fp_ci95": boot_ci_vals([float(x) for x in fps], rng),
        "line_drift_rate": drift_rate,
        "val_w": val_w,
        "recall_line_only": recall_line_only,
        "detected_gt_line_only": len(detected_line),
        "total_gt": total_gt,
        "detected_gt": len(detected),
        "drift_gt": len(drift),
        "surface": surface,
        "prov": cell["prov"],
    }


def maj_point(pts, N):
    kmaj = N // 2 + 1
    for p in pts:
        if p["k"] == kmaj:
            return p
    return pts[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default=FIXT)
    ap.add_argument("--json-out", default=os.path.join(ROOT, "results", "m2_summary.json"))
    args = ap.parse_args()
    gts = load_gt()
    cells = load_cells(args.fixtures)
    out = {}
    for cname in sorted(cells):
        cell = cells[cname]
        res = analyze_cell(cell, gts.get((cell["prov"] or {}).get("target", "?"), []))
        if res is None:
            print(f"\n=== {cname}: 0 runs (skip) ===")
            continue
        out[cname] = res
        p = cell["prov"] or {}
        N = res["N"]
        odd = "" if res["N_odd"] else "  [WARN: N even]"
        print(
            f"\n=== {cname}  (target={p.get('target')} model={p.get('model')} temp={p.get('temp')} "
            f"seed={p.get('seed_mode')} thr={p.get('num_thread')} N={N}{odd}) ==="
        )
        print(f"  schema_valid={res['schema_valid_rate']} empty={res['empty_rate']} mean_issues={res['mean_issues']}")
        jc = res["jaccard"]
        ci = res["jaccard_ci95"]
        print(
            f"  Jaccard strict={jc['strict']}{ci['strict']} ±2={jc['relaxed2']}{ci['relaxed2']} ±5={jc['relaxed5']}{ci['relaxed5']}"
        )
        if res["total_gt"]:
            print(
                f"  precision={res['precision']}{res['precision_ci95']} recall={res['recall']}{res['recall_ci95']} "
                f"recall_lineonly={res['recall_line_only']} "
                f"FP/run={res['fp_per_run']} drift_rate={res['line_drift_rate']} "
                f"(detected {res['detected_gt']}/{res['total_gt']} cat, {res['detected_gt_line_only']}/{res['total_gt']} line; drift {res['drift_gt']})"
            )
        else:
            print(f"  (clean/decoy: no GT) FP/run={res['fp_per_run']}{res['fp_ci95']} precision=None")
        print(f"  多数決(k>N/2={N // 2 + 1}) FP/FN/TP — キー粒度別 no-free-lunch:")
        for w in (0, 2, 5):
            mp = maj_point(res["surface"][w], N)
            print(f"    w=±{w}: TP={mp['TP']} FP={mp['FP']} FN={mp['FN']}  (total_gt={res['total_gt']})")
    with open(args.json_out, "w", encoding="utf-8") as w:
        json.dump(out, w, ensure_ascii=False, indent=1)
    print(f"\nwrote {args.json_out}")


if __name__ == "__main__":
    main()
