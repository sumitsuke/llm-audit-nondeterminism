#!/usr/bin/env python3
"""
seed_probe: temp0(greedy) で seed が実際に出力を変えるか(=活性か)を直接検証する。
- 同一seedを複数回 -> 残差(reduction-order/batch)の有無
- 別seedを複数種  -> seed活性の有無
byte(raw sha)で比較。R1-1(A/C矛盾)の機序決着用。stdlibのみ。
"""

import json, sys, time, urllib.request, hashlib, os

OLLAMA = "http://localhost:11434/api/generate"
HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(os.path.dirname(HERE), "targets", "target_a.py")
MODEL = sys.argv[1] if len(sys.argv) > 1 else "qwen2.5-coder:1.5b"

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

code = open(TARGET, encoding="utf-8").read()
numbered = "\n".join(f"{i + 1}: {ln}" for i, ln in enumerate(code.splitlines()))
PROMPT = (
    "You are a security/correctness code auditor. Audit the following Python code and "
    "report every real defect with 1-based line_number, a category from the allowed set, "
    "severity, and a short description. Only report genuine defects. Respond as JSON.\n\n"
    f"```python\n{numbered}\n```"
)


def call(seed, temp=0.0, num_thread=4):
    body = {
        "model": MODEL,
        "prompt": PROMPT,
        "stream": False,
        "format": SCHEMA,
        "options": {
            "temperature": temp,
            "num_ctx": 4096,
            "num_predict": 1024,
            "num_thread": num_thread,
            "seed": seed,
            "top_k": 1,
            "top_p": 1.0,
        },
    }
    req = urllib.request.Request(OLLAMA, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=600) as r:
        resp = json.loads(r.read().decode()).get("response", "")
    return hashlib.sha256(resp.encode()).hexdigest()[:12], time.time() - t0


print("warmup...")
call(0)

# Group1: same seed x6 (residual test)
print("\n[Group1] temp0 seed=777 x6 (within-seed residual):")
g1 = []
for k in range(6):
    sha, dt = call(777)
    g1.append(sha)
    print(f"  run{k}: {sha} ({dt:.1f}s)")

# Group2: different seeds x6 (seed-activity test)
print("\n[Group2] temp0 seeds 1,2,3,101,202,303 (between-seed):")
g2 = []
for s in [1, 2, 3, 101, 202, 303]:
    sha, dt = call(s)
    g2.append(sha)
    print(f"  seed{s}: {sha} ({dt:.1f}s)")

u1, u2 = len(set(g1)), len(set(g2))
allshas = set(g1) | set(g2)
print("\n===== VERDICT =====")
print(f"Group1 within-seed unique: {u1}/6  -> residual(reduction-order) {'PRESENT' if u1 > 1 else 'absent'}")
print(f"Group2 between-seed unique: {u2}/6")
print(f"total distinct raw across all 12: {len(allshas)}")
if u1 == 1 and u2 == 1 and set(g1) == set(g2):
    print("=> temp0 fully deterministic here; seed INACTIVE (all identical).")
elif u2 <= u1:
    print(
        "=> between-seed variation NOT greater than within-seed => seed INACTIVE; "
        "variation is reduction-order/batch RESIDUAL, not seed."
    )
else:
    print("=> between-seed variation exceeds within-seed => seed appears ACTIVE at temp0 (unexpected).")
