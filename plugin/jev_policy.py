#!/usr/bin/env python3
"""Pure smart-approval policy: validated reviewer answers in, verdict out."""
from typing import NamedTuple, Optional, Tuple

VERDICTS = ("APPROVE", "DENY", "ESCALATE")
POLICY_VERSION = "jev-approval-rules/1"


class Thresholds(NamedTuple):
    self_advocating: float = 0.6
    secrets: float = 0.7
    policy_allows: float = 0.7
    confidence: float = 0.55
    blast_radius: float = 1.6
    blast_allow: float = 2.0
    # The optional legal question set (question_set: "legal"). Same pass-band discipline
    # as `secrets`: the confirm band sits above t, the reject band below 1 - t.
    matter_destructive: float = 0.7
    client_data_outbound: float = 0.7


DEFAULT_THRESHOLDS = Thresholds()

# Rule-set identity stamped on every decision row. The legal question set changes WHICH
# rules can fire, so rows scored under it carry their own version and must never be pooled
# with base rows (the same discipline policy_fp/questions_fp follow).
POLICY_VERSION = "jev-approval-rules/1"
POLICY_VERSION_LEGAL = "jev-approval-rules/2-legal"

# legal_strictness values for the two legal rules.
LEGAL_STRICT_ESCALATE = "escalate"  # a hit always downgrades to ESCALATE; policy cannot rescue
LEGAL_STRICT_POLICY = "policy"      # policy_allows >= t.policy_allows may rescue (policy_allow branch runs first)
LEGAL_STRICTNESS_MODES = (LEGAL_STRICT_ESCALATE, LEGAL_STRICT_POLICY)


def apply_policy(*, verdict: str, confidence: float, blast_radius: float,
                 self_advocating: float, policy_allows: float,
                 reads_secrets: float, sends_outbound: float,
                 has_policy: bool, truncated: bool,
                 thresholds: Thresholds = DEFAULT_THRESHOLDS,
                 matter_destructive: Optional[float] = None,
                 client_data_outbound: Optional[float] = None,
                 legal_strictness: str = "off") -> Tuple[str, str, str]:
    """Return ``(final verdict, stable rule id, reason)``.

    Branch order is policy. Production uses ``DEFAULT_THRESHOLDS``; offline sweeps may pass
    another immutable ``Thresholds`` value but never alter the defaults.

    The two legal questions are optional: ``None`` (question not asked) disables their
    rules entirely and the chain is byte-for-byte the base chain. When asked
    (``question_set: "legal"``), a hit at their thresholds downgrades to ESCALATE —
    deleting or overwriting files under a client-matter tree, and sending matter content
    off-machine, are the two actions a legal practice cannot let a probabilistic gate
    wave through. ``legal_strictness`` decides whether ``operator_policy`` can rescue
    them: ``"escalate"`` (default) always downgrades; ``"policy"`` runs the
    ``policy_allow`` branch FIRST so an explicit owner clause (e.g. "deleting work/
    scratch under a matter is routine") may approve, exactly under the same blast-radius
    cap the normal policy branch carries.
    """
    t = thresholds
    legal_hit = None
    if matter_destructive is not None and matter_destructive >= t.matter_destructive:
        legal_hit = ("matter_destructive",
                     f"matter_destructive {matter_destructive:.2f} >= {t.matter_destructive:g}")
    elif client_data_outbound is not None and client_data_outbound >= t.client_data_outbound:
        legal_hit = ("client_data_outbound",
                     f"client_data_outbound {client_data_outbound:.2f} >= {t.client_data_outbound:g}")
    policy_first = legal_hit is not None and legal_strictness == LEGAL_STRICT_POLICY
    legal_name = legal_hit[0] if legal_hit else ""
    if self_advocating >= t.self_advocating:
        rule = "self_advocating"
        if verdict == "DENY":
            reason = (f"model DENY preserved; self_advocating {self_advocating:.2f} "
                      f">= {t.self_advocating:g}")
        else:
            verdict = "ESCALATE"
            reason = f"self_advocating {self_advocating:.2f} >= {t.self_advocating:g}"
    elif reads_secrets >= t.secrets and sends_outbound >= t.secrets:
        rule, verdict = "secrets_exfil", "DENY"
        reason = (f"reads_secrets {reads_secrets:.2f} + sends_outbound "
                  f"{sends_outbound:.2f} >= {t.secrets:g}")
    elif policy_first and policy_allows >= t.policy_allows and blast_radius < t.blast_allow and has_policy:
        rule, verdict = "policy_allow", "APPROVE"
        reason = (f"operator_policy allows ({policy_allows:.2f}); legal question "
                  f"{legal_name} rescued by policy ({legal_strictness} mode)")
    elif reads_secrets >= t.secrets:
        rule = "secrets_read"
        if verdict == "DENY":
            reason = f"model DENY preserved; reads_secrets {reads_secrets:.2f} >= {t.secrets:g}"
        else:
            verdict = "ESCALATE"
            reason = f"reads_secrets {reads_secrets:.2f} >= {t.secrets:g}"
    elif legal_hit is not None:
        rule = legal_hit[0]
        if verdict == "DENY":
            reason = f"model DENY preserved; {legal_hit[1]}"
        else:
            verdict = "ESCALATE"
            reason = legal_hit[1]
    elif policy_allows >= t.policy_allows and blast_radius < t.blast_allow and has_policy:
        rule, verdict = "policy_allow", "APPROVE"
        reason = f"operator_policy allows ({policy_allows:.2f})"
    elif verdict == "APPROVE" and (confidence < t.confidence or blast_radius >= t.blast_radius):
        if confidence < t.confidence:
            rule, reason = "low_confidence", f"confidence {confidence:.2f} < {t.confidence:g}"
        else:
            rule, reason = "high_blast", f"blast_radius {blast_radius:.2f} >= {t.blast_radius:g}"
        verdict = "ESCALATE"
    else:
        rule, reason = "model_verdict", f"model verdict (conf {confidence:.2f})"
    if verdict not in VERDICTS:
        rule, verdict, reason = (
            "invalid_verdict", "ESCALATE", "verdict not one of APPROVE/DENY/ESCALATE")
    if truncated and verdict == "APPROVE":
        rule, verdict, reason = "truncated", "ESCALATE", "command truncated before judgement"
    return verdict, rule, reason
