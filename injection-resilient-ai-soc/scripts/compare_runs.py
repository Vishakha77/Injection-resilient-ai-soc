#!/usr/bin/env python3
"""Compare metrics of two saved runs side by side.
Usage: python3 scripts/compare_runs.py results/runs/simulated results/runs/ollama_llama3.1_8b
"""
import json, sys, os
import pandas as pd

a, b = sys.argv[1], sys.argv[2]
na, nb = os.path.basename(a.rstrip("/")), os.path.basename(b.rstrip("/"))
A = pd.read_csv(f"{a}/metrics.csv").set_index("config")
B = pd.read_csv(f"{b}/metrics.csv").set_index("config")
for d in (a, b):
    try:
        print(d, json.load(open(f"{d}/meta.json")))
    except FileNotFoundError:
        pass
cols = ["detection_rate_%", "attack_success_injected_%", "attack_success_adaptive_%", "false_positive_rate_%", "escalated_%"]
rows = []
for cfg in A.index:
    r = {"config": cfg}
    for c in cols:
        short = c.replace("_%", "").replace("attack_success_", "AS_").replace("detection_rate", "DR") \
                 .replace("false_positive_rate", "FPR").replace("escalated", "esc")
        r[f"{short} [{na}]"] = A.loc[cfg, c]
        r[f"{short} [{nb}]"] = B.loc[cfg, c] if cfg in B.index else None
    rows.append(r)
pd.set_option("display.width", 250); pd.set_option("display.max_columns", 50)
print(pd.DataFrame(rows).set_index("config").to_string())
