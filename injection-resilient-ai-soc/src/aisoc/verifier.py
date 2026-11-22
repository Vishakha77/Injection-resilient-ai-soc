"""Cross-model verification: fuse Judge A (flow ML), Judge B (LLM), Judge C (injection).

Decisions:
  ALERT    - confirmed malicious, goes to the alert queue
  ESCALATE - judges disagree; a human must look (never auto-closed)
  CLOSE    - all judges agree it is benign

Key property: an attacker who fools the LLM still has to fool a model that never
reads text (A) AND avoid tripping the injection detector (C).
"""
from dataclasses import dataclass


@dataclass
class Policy:
    tau_flow: float = 0.5        # Judge A malicious threshold
    tau_inj: float = 0.5         # Judge C injection threshold
    use_flow: bool = True
    use_inj: bool = True


def decide(llm_label, p_flow, p_inj, pol: Policy):
    reasons = []
    if pol.use_inj and p_inj >= pol.tau_inj:
        reasons.append(f"prompt-injection payload in traffic (p={p_inj:.2f})")
        return "ALERT", reasons
    flow_mal = pol.use_flow and p_flow >= pol.tau_flow
    if llm_label == "malicious":
        if pol.use_flow and not flow_mal:
            reasons.append(f"LLM malicious, flow model benign (p={p_flow:.2f})")
        return "ALERT", reasons or ["LLM malicious"]
    if flow_mal:
        reasons.append(f"LLM said benign but flow model disagrees (p={p_flow:.2f})")
        return "ESCALATE", reasons
    return "CLOSE", ["all judges benign"]
