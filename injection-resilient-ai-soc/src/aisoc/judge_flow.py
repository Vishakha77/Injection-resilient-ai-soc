"""Judge A - flow-feature ML model.

Sees ONLY numbers produced by the sensor (counters, timings, per-host behaviour,
Suricata alert metadata). It never reads a byte of attacker-written text, so it
cannot be prompt-injected. Explanations via SHAP.
"""
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

APP = ["http", "dns", "failed", "none"]
FEATURES = [
    "dest_port", "is_tcp", "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
    "bytes_ratio", "age", "tcp_syn", "tcp_fin", "tcp_rst", "tcp_psh", "http_status", "is_post",
    "http_resp_len", "alert_count", "alert_max_sev", *[f"app_{a}" for a in APP],
    # per-source behaviour in the whole capture window (computed from telemetry only)
    "src_flows", "src_distinct_dports", "src_distinct_dsts", "src_http_4xx_ratio",
    "src_interval_cv", "dns_qlen", "dns_qlabel_max", "dns_qentropy",
]


def _entropy(s):
    if not s:
        return 0.0
    _, c = np.unique(list(s), return_counts=True)
    p = c / c.sum()
    return float(-(p * np.log2(p)).sum())


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    X = pd.DataFrame(index=df.index)
    X["dest_port"] = df["dest_port"]
    X["is_tcp"] = (df["proto"] == "TCP").astype(int)
    for c in ["pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "age",
              "tcp_syn", "tcp_fin", "tcp_rst", "tcp_psh", "http_status", "http_resp_len"]:
        X[c] = df[c]
    X["bytes_ratio"] = df["bytes_toserver"] / (df["bytes_toclient"] + 1)
    X["is_post"] = (df["http_method"] == "POST").astype(int)
    # Attack-signature alerts only: injection-indicator rules (sid 12xxxxx) belong to Judge C,
    # so the two judges stay independent.
    atk = df.apply(lambda r: [sv for sid, sv in zip(r["alert_sids"], r["alert_sevs"]) if sid < 1200000], axis=1)
    X["alert_count"] = atk.apply(len)
    X["alert_max_sev"] = atk.apply(lambda s: 4 - min(s) if s else 0)  # 3 = most severe, 0 = none
    for a in APP:
        X[f"app_{a}"] = (df["app_proto"] == a).astype(int)
    g = df.groupby("src_ip")
    X["src_flows"] = g["src_port"].transform("count")
    X["src_distinct_dports"] = g["dest_port"].transform("nunique")
    X["src_distinct_dsts"] = g["dest_ip"].transform("nunique")
    is4 = (df["http_status"] >= 400).astype(int)
    X["src_http_4xx_ratio"] = is4.groupby(df["src_ip"]).transform("mean")

    def cv(s):
        s = np.sort(s.values)
        if len(s) < 3:
            return pd.Series(1.0, index=None)
        d = np.diff(s)
        return d.std() / (d.mean() + 1e-9)
    cvs = g["start"].apply(lambda s: cv(s) if len(s) >= 3 else 1.0)
    X["src_interval_cv"] = df["src_ip"].map(cvs).astype(float)
    # DNS query SHAPE only (length, label length, entropy) - not its words.
    q = df["untrusted"].apply(lambda u: u.get("dns.query", ""))
    X["dns_qlen"] = q.str.len()
    X["dns_qlabel_max"] = q.apply(lambda s: max((len(x) for x in s.split(".")), default=0))
    X["dns_qentropy"] = q.apply(_entropy)
    return X[FEATURES].astype(float)


class FlowJudge:
    def __init__(self):
        self.model = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, random_state=7)

    def fit(self, df):
        X, y = build_features(df), (df["label"] == "malicious").astype(int)
        self.model.fit(X, y)
        return self

    def predict_proba(self, df):
        return self.model.predict_proba(build_features(df))[:, 1]

    def explain(self, df, top_k=3):
        """Top-k SHAP feature contributions per row (falls back gracefully if shap missing)."""
        X = build_features(df)
        try:
            import shap
            ex = shap.TreeExplainer(self.model)
            sv = ex.shap_values(X)
            sv = sv[1] if isinstance(sv, list) else sv
        except Exception:
            return [""] * len(X)
        out = []
        for i in range(len(X)):
            idx = np.argsort(-np.abs(sv[i]))[:top_k]
            out.append("; ".join(f"{FEATURES[j]}={X.iloc[i, j]:.3g} ({sv[i][j]:+.2f})" for j in idx))
        return out

    def save(self, path):
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path):
        j = cls()
        j.model = joblib.load(path)
        return j
