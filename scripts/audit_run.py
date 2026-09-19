#!/usr/bin/env python3
"""
audit_run.py — 第1層(非決定・生成)。同一targetを構造化出力でN回監査し raw を凍結。
- warmup(ダミー投入→破棄)でKV/cold run交絡を統制
- 各runに params/hash/backend/model-digest を記録
- fixtures/audit_logs.jsonl へ 1行=1run で追記(cellメタ付き)
依存は stdlib のみ(urllib)。時刻は環境依存を避け記録しない(再現性のため)。

例:
  python audit_run.py --target ../targets/target_a.py --model qwen2.5-coder:1.5b \
       --temp 0.7 --seed-mode vary --thread 4 --n 51 --cell d_15b_a
"""

import json, time, urllib.request, hashlib, os, argparse, platform

OLLAMA_GEN = "http://localhost:11434/api/generate"
OLLAMA_SHOW = "http://localhost:11434/api/show"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXT = os.path.join(ROOT, "fixtures", "audit_logs.jsonl")
GT = os.path.join(ROOT, "results", "gt.csv")

CATEGORIES = [
    "SQLInjection",
    "NullDereference",
    "SilentExceptionSwallow",
    "HardcodedSecret",
    "OffByOne",
    "ResourceLeak",
    "PathTraversal",
    "CommandInjection",
    "CodeInjection",
    "Other",
    "Unclear",
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
SCHEMA_HASH = hashlib.sha256(json.dumps(SCHEMA, sort_keys=True).encode()).hexdigest()[:12]


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


def build_prompt(code):
    numbered = "\n".join(f"{i + 1}: {ln}" for i, ln in enumerate(code.splitlines()))
    return (
        "You are a security/correctness code auditor. Audit the following Python code and "
        "report every real defect. For each issue give the 1-based line_number (use the number "
        "shown at the start of each line), a category from the allowed set, a severity, and a "
        "short description. Only report genuine defects; if there are none, return an empty list. "
        "Respond as JSON matching the schema.\n\n"
        f"```python\n{numbered}\n```"
    )


def post(url, body):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read().decode("utf-8"))


def model_digest(model):
    try:
        info = post(OLLAMA_SHOW, {"model": model})
        d = info.get("details", {})
        return {"quant": d.get("quantization_level"), "param": d.get("parameter_size"), "family": d.get("family")}
    except Exception as e:
        return {"error": str(e)}


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def ollama_version():
    try:
        return _get("http://localhost:11434/api/version").get("version")
    except Exception as e:
        return f"err:{e}"


def backend(model):
    """best-effort: size_vram>0 => GPU, else CPU。reduction-order残差の機序変数。"""
    try:
        for m in _get("http://localhost:11434/api/ps").get("models", []):
            if m.get("name") == model or m.get("model") == model:
                return "GPU" if m.get("size_vram", 0) else "CPU"
        return "CPU(not-loaded)"
    except Exception as e:
        return f"err:{e}"


def call(prompt, seed, temp, num_thread, model):
    body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": SCHEMA,
        "options": {"temperature": temp, "num_ctx": 4096, "num_predict": 1024, "num_thread": num_thread},
    }
    if seed is not None:
        body["options"]["seed"] = seed
    if temp == 0:
        body["options"]["top_k"] = 1
        body["options"]["top_p"] = 1.0
    t0 = time.time()
    out = post(OLLAMA_GEN, body)
    return out.get("response", ""), time.time() - t0, out


def parse(resp):
    try:
        obj = json.loads(resp)
        issues = obj.get("issues", [])
        if not isinstance(issues, list):
            return None, False
        norm = []
        for it in issues:
            norm.append(
                {
                    "line_number": it.get("line_number"),
                    "category": str(it.get("category", "")).strip(),
                    "severity": it.get("severity"),
                    "description": it.get("description"),
                }
            )
        return norm, True
    except Exception:
        return None, False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--model", default="qwen2.5-coder:1.5b")
    ap.add_argument("--temp", type=float, default=0.7)
    ap.add_argument("--seed-mode", choices=["fixed", "vary"], default="vary")
    ap.add_argument("--seed", type=int, default=0)  # fixed 時の値 / vary 時は run index
    ap.add_argument("--thread", type=int, default=4)
    ap.add_argument("--n", type=int, default=51)
    ap.add_argument("--cell", required=True, help="cell label (e.g. d_15b_a)")
    ap.add_argument("--out", default=FIXT)
    args = ap.parse_args()

    code = open(args.target, encoding="utf-8").read()
    prompt = build_prompt(code)
    tgt_name = os.path.basename(args.target)
    prov = {
        "cell": args.cell,
        "target": tgt_name,
        "target_hash": sha(code),
        "model": args.model,
        "model_digest": model_digest(args.model),
        "temp": args.temp,
        "seed_mode": args.seed_mode,
        "num_thread": args.thread,
        "num_ctx": 4096,
        "num_predict": 1024,
        "prompt_hash": sha(prompt),
        "schema_hash": SCHEMA_HASH,
        "n": args.n,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    print(f"[{args.cell}] warmup...")
    call(prompt, args.seed, args.temp, args.thread, args.model)  # discard (KV/cold run統制)
    # 環境メタ(warmup後にbackend確定・再現性の機序変数)
    gt_hash = sha(open(GT, encoding="utf-8").read()) if os.path.exists(GT) else None
    prov.update(
        {
            "ollama_version": ollama_version(),
            "backend": backend(args.model),
            "os": platform.platform(),
            "cpu": platform.processor() or platform.machine(),
            "gt_hash": gt_hash,
        }
    )

    with open(args.out, "a", encoding="utf-8") as w:
        w.write(json.dumps({"type": "provenance", **prov}, ensure_ascii=False) + "\n")
        w.flush()
        for k in range(args.n):
            s = k if args.seed_mode == "vary" else args.seed
            resp, dt, _ = call(prompt, s, args.temp, args.thread, args.model)
            issues, valid = parse(resp)
            rec = {
                "type": "run",
                "cell": args.cell,
                "run_id": k,
                "seed": s,
                "raw_sha": sha(resp),
                "schema_valid": valid,
                "n_issues": (len(issues) if issues is not None else None),
                "issues": issues,
                "gen_s": round(dt, 2),
            }
            w.write(json.dumps(rec, ensure_ascii=False) + "\n")
            w.flush()  # ライブ読み取りで末尾切れを避ける
            if k % 10 == 0:
                print(f"  [{args.cell}] run {k}: sha={rec['raw_sha']} issues={rec['n_issues']} ({dt:.1f}s)")
    print(f"[{args.cell}] done N={args.n} -> {args.out}")


if __name__ == "__main__":
    main()
