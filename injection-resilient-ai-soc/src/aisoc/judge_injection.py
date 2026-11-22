"""Judge C - prompt-injection detector on attacker-controlled fields.

Turns the attacker's injection attempt into evidence AGAINST them: benign clients
never send instructions addressed to an AI analyst. Two signals:
  1. char n-gram TF-IDF + logistic regression (robust to leetspeak / spacing tricks)
  2. Suricata section-2 rules (sid 12000xx) already fired by the sensor
"""
import base64
import random
import re

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from . import payloads as P
from .traffic_gen import BENIGN_PATHS, UAS

INJ_SIDS = range(1200000, 1300000)
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def normalise(text: str) -> str:
    t = text.replace("+", " ").replace("%20", " ").replace("-", " ")
    # decode embedded base64 blobs so encoded instructions are visible
    for m in B64.findall(text):
        try:
            d = base64.b64decode(m + "=" * (-len(m) % 4)).decode("utf-8")
            if d.isprintable():
                t += " " + d
        except Exception:
            pass
    return t.lower()


def untrusted_text(u: dict) -> str:
    return " | ".join(v for v in u.values() if v)


def _training_corpus(seed=0):
    r = random.Random(seed)
    pos, neg = [], []
    benign_ctx = BENIGN_PATHS + UAS + P.HARD_NEGATIVE_TEXT[: len(P.HARD_NEGATIVE_TEXT) // 2 + 2] + P.HARD_NEGATIVE_DNS[:2]
    for _ in range(600):
        ctx = r.choice(benign_ctx)
        inj = r.choice(P.TRAIN_INJECTIONS + P.DNS_TRAIN_INJECTIONS)
        pos.append(f"{ctx} {inj}" if r.random() < 0.6 else f"{ctx} | {inj}")
        neg.append(" | ".join(r.sample(benign_ctx, k=r.randint(1, 3))))
    return pos + neg, [1] * len(pos) + [0] * len(neg)


class InjectionJudge:
    def __init__(self):
        self.model = make_pipeline(
            TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), preprocessor=normalise, min_df=2, sublinear_tf=True),
            LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced"),
        )

    def fit(self):
        X, y = _training_corpus()
        self.model.fit(X, y)
        return self

    def score(self, df):
        texts = df["untrusted"].apply(untrusted_text).tolist()
        p = self.model.predict_proba(texts)[:, 1]
        rule_hit = df["alert_sids"].apply(lambda s: any(x in INJ_SIDS for x in s)).values
        return np.maximum(p, rule_hit.astype(float)), rule_hit

    def save(self, path):
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path):
        j = cls()
        j.model = joblib.load(path)
        return j
