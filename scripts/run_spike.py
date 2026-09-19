#!/usr/bin/env python3
"""
Spike: 同じコードを qwen2.5-coder に structured-output(JSON) で N回監査させ、
(line_number, category) 複合キー集合の run間 Jaccard を測る。
テーゼ成立判定用（#1 の M0/M2 規律）。依存は stdlib のみ(urllib)。
"""

import json, time, itertools, urllib.request, hashlib, os, argparse

OLLAMA = "http://localhost:11434/api/generate"
HERE = os.path.dirname(os.path.abspath(__file__))
# 既定は clean な de-labeled target。旧・汚染targetは spike/contaminated/ に隔離済。
SNIPPET = os.path.join(os.path.dirname(HERE), "targets", "target_a.py")

CATEGORIES = [
    "SQLInjection",
    "NullDereference",
    "SilentExceptionSwallow",
    "HardcodedSecret",
    "OffByOne",
    "ResourceLeak",
    "PathTraversal",
    "CommandInjection",
    "Other",
]

SCHEMA = {
    "type": "object",
    "properties": {
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "line_number": {"type": "integer"},
                    "category": {"type": "string", "enum": CATEGORIES},
                    "severity": {"type": "string", "enum": ["Low", "Medium", "High"]},
                    "description": {"type": "string"},
                },
                "required": ["line_number", "category", "severity", "description"],
            },
        }
    },
    "required": ["issues"],
}


def build_prompt(code):
    numbered = "\n".join(f"{i + 1}: {ln}" for i, ln in enumerate(code.splitlines()))
    return (
        "You are a security/correctness code auditor. Audit the following Python code and "
        "report every real defect. For each issue give the 1-based line_number (use the number "
        "shown at the start of each line), a category from the allowed set, a severity, and a "
        "short description. Only report genuine defects. Respond as JSON matching the schema.\n\n"
        f"```python\n{numbered}\n```"
    )


def call(prompt, seed, temp, num_thread, model, use_format=True):
    body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temp,
            "num_ctx": 4096,
            "num_predict": 1024,
            "num_thread": num_thread,
        },
    }
    if seed is not None:
        body["options"]["seed"] = seed
    if temp == 0:
        body["options"]["top_k"] = 1
        body["options"]["top_p"] = 1.0
    if use_format:
        body["format"] = SCHEMA
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(OLLAMA, data=data, headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=600) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    dt = time.time() - t0
    return out.get("response", ""), dt


def parse_keys(resp_text):
    """returns (set_of_composite_keys, set_of_line_keys, raw_issue_count, raw_sha)"""
    raw_sha = hashlib.sha256(resp_text.encode("utf-8")).hexdigest()[:12]
    try:
        obj = json.loads(resp_text)
        issues = obj.get("issues", [])
    except Exception:
        return set(), set(), None, raw_sha
    comp, lines = set(), set()
    for it in issues:
        ln = it.get("line_number")
        cat = str(it.get("category", "")).strip()
        comp.add(f"{ln}_{cat}")
        lines.add(str(ln))
    return comp, lines, len(issues), raw_sha


def jaccard(a, b):
    if not a and not b:
        return 1.0
    u = a | b
    return len(a & b) / len(u) if u else 1.0


def mean_pairwise(sets):
    ps = list(itertools.combinations(range(len(sets)), 2))
    if not ps:
        return 1.0, 1.0, 1.0
    vals = [jaccard(sets[i], sets[j]) for i, j in ps]
    return sum(vals) / len(vals), min(vals), max(vals)


def run_config(name, code, n, seed, temp, num_thread, model, use_format):
    prompt = build_prompt(code)
    comp_sets, line_sets, shas, counts, times = [], [], [], [], []
    for k in range(n):
        # seed 可変モード: seed が "vary" のとき run index を seed に
        s = k if seed == "vary" else seed
        resp, dt = call(prompt, s, temp, num_thread, model, use_format)
        comp, lines, cnt, sha = parse_keys(resp)
        comp_sets.append(comp)
        line_sets.append(lines)
        shas.append(sha)
        counts.append(cnt)
        times.append(dt)
        print(f"    run {k:2d}: sha={sha} issues={cnt} keys={sorted(comp)} ({dt:.1f}s)")
    jc_m, jc_lo, jc_hi = mean_pairwise(comp_sets)
    jl_m, jl_lo, jl_hi = mean_pairwise(line_sets)
    uniq_resp = len(set(shas))
    # 最頻出現率: 全 comp キーの出現頻度
    freq = {}
    for cs in comp_sets:
        for key in cs:
            freq[key] = freq.get(key, 0) + 1
    print(f"  [{name}] N={n} model={model} seed={seed} temp={temp} thread={num_thread} format={use_format}")
    print(f"    byte-unique responses: {uniq_resp}/{n}")
    print(f"    Jaccard(line,category): mean={jc_m:.3f} min={jc_lo:.3f} max={jc_hi:.3f}")
    print(f"    Jaccard(line-only)    : mean={jl_m:.3f} min={jl_lo:.3f} max={jl_hi:.3f}")
    print(
        f"    key frequency (out of {n}): "
        + ", ".join(f"{key}:{c}" for key, c in sorted(freq.items(), key=lambda x: -x[1]))
    )
    print(f"    gen time: mean={sum(times) / len(times):.1f}s total={sum(times):.1f}s")
    return {
        "name": name,
        "n": n,
        "model": model,
        "seed": seed,
        "temp": temp,
        "num_thread": num_thread,
        "format": use_format,
        "byte_unique": uniq_resp,
        "jaccard_comp_mean": jc_m,
        "jaccard_comp_min": jc_lo,
        "jaccard_line_mean": jl_m,
        "freq": freq,
        "counts": counts,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5-coder:1.5b")
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--configs", default="A,D")
    ap.add_argument("--target", default=SNIPPET, help="path to code under audit")
    args = ap.parse_args()
    code = open(args.target, encoding="utf-8").read()
    print(f"target: {args.target}")

    CONFIGS = {
        # A: 完全ピン留め（temp0/seed固定/threads固定） — M0 予測: 決定的
        "A": dict(seed=0, temp=0.0, num_thread=4, use_format=True),
        # B: threads=1
        "B": dict(seed=0, temp=0.0, num_thread=1, use_format=True),
        # C: temp0 だが seed 可変
        "C": dict(seed="vary", temp=0.0, num_thread=4, use_format=True),
        # D: temp>0（現実条件） — 予測: Jaccard<1.0
        "D": dict(seed="vary", temp=0.7, num_thread=4, use_format=True),
    }
    results = []
    # 1回ウォームアップ
    print("warming up model...")
    call(build_prompt(code), 0, 0.0, 4, args.model, True)
    for cname in args.configs.split(","):
        cname = cname.strip()
        if cname not in CONFIGS:
            continue
        print(f"\n=== CONFIG {cname} ===")
        cfg = CONFIGS[cname]
        results.append(run_config(cname, code, args.n, model=args.model, **cfg))

    print("\n===== SUMMARY =====")
    for r in results:
        print(
            f"{r['name']}: byte_unique={r['byte_unique']}/{r['n']} "
            f"Jaccard(l,c)={r['jaccard_comp_mean']:.3f} Jaccard(line)={r['jaccard_line_mean']:.3f} "
            f"[seed={r['seed']} temp={r['temp']} thr={r['num_thread']}]"
        )


if __name__ == "__main__":
    main()
