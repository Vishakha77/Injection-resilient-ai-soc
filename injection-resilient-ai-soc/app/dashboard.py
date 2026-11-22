"""AI-SOC dashboard:  streamlit run app/dashboard.py"""
import json
import os

import pandas as pd
import streamlit as st

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RES = os.path.join(ROOT, "results")

st.set_page_config(page_title="Injection-Resilient AI-SOC", layout="wide")
st.title("Injection-Resilient AI-SOC")
st.caption("Cross-model verification of LLM alert triage over Suricata")

if not os.path.exists(f"{RES}/test_final.pkl"):
    st.error("No results yet. Run:  PYTHONPATH=src python -m aisoc.cli all")
    st.stop()

df = pd.read_pickle(f"{RES}/test_final.pkl")
metrics = pd.read_csv(f"{RES}/metrics.csv")
meta = json.load(open(f"{RES}/meta.json"))
if meta.get("backend") == "simulated":
    st.warning("LLM backend = simulated (offline stand-in). Re-run with --backend ollama/openai/anthropic for real results.")

c = st.columns(5)
c[0].metric("Test flows", meta["n_test_flows"])
c[1].metric("Malicious", meta["n_malicious"])
c[2].metric("Injected attacks", meta["n_injected"])
c[3].metric("Auto-closed", int((df["final"] == "CLOSE").sum()))
c[4].metric("Escalated to human", int((df["final"] == "ESCALATE").sum()))

st.subheader("Defence comparison")
st.dataframe(metrics, width='stretch', hide_index=True)
st.bar_chart(metrics.set_index("config")[["attack_success_injected_%", "false_positive_rate_%"]])

st.subheader("Alert queue")
f1, f2, f3 = st.columns(3)
dec = f1.multiselect("Final decision", ["ALERT", "ESCALATE", "CLOSE"], default=["ALERT", "ESCALATE"])
inj = f2.multiselect("Injection type", sorted(df["injected"].unique()), default=sorted(df["injected"].unique()))
only_flip = f3.checkbox("Only cases where the LLM was fooled", value=False)
q = df[df["final"].isin(dec) & df["injected"].isin(inj)]
if only_flip:
    q = q[(q["label"] == "malicious") & (q["llm_provenance"] == "benign")]
view = q[["src_ip", "dest_ip", "dest_port", "category", "label", "injected", "llm_provenance", "p_flow", "p_inj", "final", "final_reason"]]
st.dataframe(view.round(2), width='stretch', hide_index=True, height=320)

st.subheader("Inspect one event")
if len(q):
    idx = st.selectbox("Event", q.index, format_func=lambda i: f"{df.at[i, 'category']} | {df.at[i, 'src_ip']}:{df.at[i, 'src_port']} | {df.at[i, 'final']}")
    r = df.loc[idx]
    a, b = st.columns(2)
    a.markdown("**Untrusted fields (attacker-written)**")
    a.json({k: v for k, v in r["untrusted"].items() if v})
    a.markdown("**Suricata alerts**")
    a.write(r["alert_sigs"] or "none")
    b.markdown(f"**Judge A — flow ML:** p(malicious) = {r['p_flow']:.2f}")
    b.caption(f"SHAP: {r['flow_why']}")
    b.markdown(f"**Judge B — LLM (provenance prompt):** {r['llm_provenance']}")
    b.caption(r["llm_provenance_why"])
    b.markdown(f"**Judge C — injection detector:** p = {r['p_inj']:.2f}")
    b.markdown(f"### Final: {r['final']}")
    b.write(r["final_reason"])
