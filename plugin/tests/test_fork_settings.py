#!/usr/bin/env python3
"""Fork additions: construction sentinel, dotenv-preferring custom key, settings thresholds,
and the optional legal question set. Offline, in the repo's executable-script style."""
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import types

HERE = pathlib.Path(__file__).resolve().parent
PLUGIN = HERE.parent
os.environ["JEV_APPROVAL_LOG"] = str(pathlib.Path(tempfile.mkdtemp()) / "fork.jsonl")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeConfig:
    """Stand-in for hermes_cli.config: settings come from CONFIG, dotenv values from DOTENV."""
    CONFIG = {}
    DOTENV = {}

    @staticmethod
    def load_config_readonly():
        return {"plugins": {"entries": {"jev-approvals": {"settings": dict(_FakeConfig.CONFIG)},
                                        "jev-approvals-guard": {"settings": {}}}}}

    @staticmethod
    def get_env_value_prefer_dotenv(var):
        if var in _FakeConfig.DOTENV:
            return _FakeConfig.DOTENV[var]
        return os.environ.get(var)


fake_cli = types.ModuleType("hermes_cli")
fake_config = types.ModuleType("hermes_cli.config")
fake_config.load_config_readonly = _FakeConfig.load_config_readonly
fake_config.get_env_value_prefer_dotenv = _FakeConfig.get_env_value_prefer_dotenv
fake_cli.config = fake_config
sys.modules.setdefault("hermes_cli", fake_cli)
sys.modules["hermes_cli.config"] = fake_config

policy = load("jev_policy_fork", PLUGIN / "jev_policy.py")
jev = load("jev_plugin_fork", PLUGIN / "__init__.py")

# ── 1. base chain is untouched when the legal questions are not asked ────────────────
BASE = dict(verdict="APPROVE", confidence=0.9, blast_radius=0.1,
            self_advocating=0.01, policy_allows=0.02, reads_secrets=0.01,
            sends_outbound=0.01, has_policy=False, truncated=False)
assert policy.apply_policy(**BASE) == ("APPROVE", "model_verdict", "model verdict (conf 0.90)")
assert policy.apply_policy(**BASE, matter_destructive=None,
                           client_data_outbound=None) == policy.apply_policy(**BASE)

# ── 2. legal rules: strict escalate is the default, model DENY is preserved ──────────
legal = dict(BASE, matter_destructive=0.85, client_data_outbound=0.2,
             legal_strictness="escalate")
assert policy.apply_policy(**legal)[:2] == ("ESCALATE", "matter_destructive")
assert policy.apply_policy(**dict(legal, verdict="DENY"))[0] == "DENY"
outbound = dict(BASE, matter_destructive=0.1, client_data_outbound=0.9,
                legal_strictness="escalate")
assert policy.apply_policy(**outbound)[:2] == ("ESCALATE", "client_data_outbound")
# below threshold -> no rule, no trace
calm = dict(BASE, matter_destructive=0.3, client_data_outbound=0.3,
            legal_strictness="escalate")
assert policy.apply_policy(**calm) == ("APPROVE", "model_verdict", "model verdict (conf 0.90)")

# ── 3. strictness: 'escalate' beats a covering policy; 'policy' lets it rescue ───────
covered = dict(BASE, matter_destructive=0.9, client_data_outbound=0.1,
               policy_allows=0.9, has_policy=True, legal_strictness="escalate")
assert policy.apply_policy(**covered)[:2] == ("ESCALATE", "matter_destructive")
rescued = dict(covered, legal_strictness="policy")
res = policy.apply_policy(**rescued)
assert res[0] == "APPROVE" and res[1] == "policy_allow" and "rescued" in res[2]
# policy rescue keeps the blast cap: at/above blast_allow it is not rescuable
severe = dict(rescued, blast_radius=2.0)
assert policy.apply_policy(**severe)[:2] == ("ESCALATE", "matter_destructive")
# a legal hit never beats the credential-exfiltration DENY
exfil = dict(BASE, matter_destructive=0.9, reads_secrets=0.9, sends_outbound=0.9,
             legal_strictness="escalate")
assert policy.apply_policy(**exfil)[:2] == ("DENY", "secrets_exfil")

# ── 4. thresholds: valid override applies; unknown/invalid keys are dropped ──────────
_FakeConfig.CONFIG = {"thresholds": {"confidence": 0.8, "blast_radius": 1.2,
                                     "nonsense": 0.5, "secrets": "high", "policy_allows": 9}}
thresholds, custom = jev._thresholds()
assert custom is True
assert thresholds.confidence == 0.8 and thresholds.blast_radius == 1.2
assert thresholds.secrets == 0.7 and thresholds.policy_allows == 0.7  # invalid/unknown dropped
# the override actually moves the gate
gate = dict(BASE, confidence=0.6)
assert policy.apply_policy(**gate) == ("APPROVE", "model_verdict", "model verdict (conf 0.60)")
assert policy.apply_policy(**gate, thresholds=thresholds)[:2] == ("ESCALATE", "low_confidence")
_FakeConfig.CONFIG = {}
thresholds, custom = jev._thresholds()
assert custom is False and thresholds == policy.DEFAULT_THRESHOLDS

# ── 5. question set: base by default, legal adds exactly two; fingerprint follows ────
questions, asked, strictness, thresholds, custom = jev._questions()
assert asked is False and set(questions) == set(jev.QUESTIONS)
_FakeConfig.CONFIG = {"question_set": "legal", "legal_strictness": "policy"}
questions, asked, strictness, thresholds, custom = jev._questions()
assert asked is True and strictness == "policy"
assert set(questions) - set(jev.QUESTIONS) == {"matter_destructive", "client_data_outbound"}
fp_base = jev._fingerprint(json.dumps(jev.QUESTIONS, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
fp_legal = jev._fingerprint(json.dumps(questions, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
assert fp_base != fp_legal
# unknown strictness tightens instead of loosening
_FakeConfig.CONFIG = {"question_set": "legal", "legal_strictness": "yolo"}
_, asked, strictness, _, _ = jev._questions()
assert asked is True and strictness == "escalate"
_FakeConfig.CONFIG = {}

# ── 6. construction sentinel: minted only for custom-endpoint mode, never over a real key
SENTINEL = "TYPESAFE_API_KEY"
saved = os.environ.pop(SENTINEL, None)
_FakeConfig.DOTENV = {}
try:
    # no key_env -> untouched (TypeSafe-direct keeps its honest contract)
    jev._ensure_construction_credential()
    assert not os.environ.get(SENTINEL)
    # key_env set -> sentinel minted
    _FakeConfig.CONFIG = {"key_env": "MY_JEV_PORTAL_KEY"}
    jev._ensure_construction_credential()
    minted = os.environ.get(SENTINEL, "")
    assert minted.startswith("jev-approvals construction sentinel")
    # an existing value (real key or operator placeholder) is never replaced
    os.environ[SENTINEL] = "sk-real-value"
    jev._ensure_construction_credential()
    assert os.environ[SENTINEL] == "sk-real-value"
    # a .env-resolvable value also suppresses the mint
    os.environ.pop(SENTINEL, None)
    _FakeConfig.DOTENV = {SENTINEL: "sk-from-dotenv"}
    jev._ensure_construction_credential()
    assert not os.environ.get(SENTINEL)
finally:
    os.environ.pop(SENTINEL, None)
    if saved is not None:
        os.environ[SENTINEL] = saved
    _FakeConfig.CONFIG = {}
    _FakeConfig.DOTENV = {}

# ── 7. custom-host wire key now honours .env-over-environ precedence ─────────────────
os.environ["MY_JEV_PORTAL_KEY"] = "from-environ"
_FakeConfig.DOTENV = {"MY_JEV_PORTAL_KEY": "from-dotenv"}
_FakeConfig.CONFIG = {"key_env": "MY_JEV_PORTAL_KEY"}
assert jev._api_key("https://jev.example/v1/systemone") == "from-dotenv"
_FakeConfig.DOTENV = {}
assert jev._api_key("https://jev.example/v1/systemone") == "from-environ"
_FakeConfig.CONFIG = {}
os.environ.pop("MY_JEV_PORTAL_KEY", None)
_FakeConfig.DOTENV = {}

print("fork settings contract: OK")
