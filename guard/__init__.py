"""jev-approvals-guard — widen what reaches the approval gate; never narrow it.

Core's dangerous-command regex flags ~11% of commands, and the shapes it misses include
exactly the ones a legal practice fears most: uploading a client document
(`curl --data @file`, `-F @file`), copying matter trees off-machine (`scp`, `rsync`,
`gsutil`/`aws s3`), and piping local files into network tools. jev-approvals (the
model-provider sibling in this repo) reviews only what core sends it, and deliberately
registers no hooks — its own README calls the gap out and points at new core patterns.

This plugin closes the gap from the OTHER side, inside the documented hook contract:

    pre_tool_call -> {"action": "approve"}  escalates the call to the EXISTING
                    human-approval gate.

The consequences fall out of core's own semantics, which is the point:
  - interactive CLI/TUI: a person is shown the command before it runs;
  - approvals.mode: smart: the gate runs the smart reviewer — the Jev sibling judges a
    command core would never have sent it;
  - unattended sessions (single-query workers, cron): the human gate resolves from
    approvals.single_query_mode / cron_mode (default deny) — the command is blocked with
    the ordinary BLOCKED message, fail closed.

It can only ADD gating. There is no directive in the hook contract that runs a tool, and
this plugin never returns one: no `modify`, no auto-run, no allowlist writes. A block
directive is likewise never returned — blocking here would deny the operator's own routine
commands without review, which is the gate's job, not this plugin's.

Fail-safe behaviour is inherited from the hook runner: a callback that raises or exceeds
plugins.hook_callback_timeout FAILS CLOSED (the tool call is blocked), so this guard can
never become a silent allow-path. Everything here is also written to survive its own
misconfiguration: an invalid pattern is dropped with a warning, not a crash.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

PLUGIN_ID = "jev-approvals-guard"

# Built-in egress shapes core's pattern list does not carry. Each is (name, compiled re).
# Scope discipline: every pattern names an OUTBOUND transfer of local content. A bare
# `curl https://api` (no body) is not a match; `--data @file`, `--form file=@`, `-T file`
# are. Shell-operator chaining (`;`, `&&`, `|`) is preserved by NOT anchoring matches, so a
# benign-looking command with a hostile second clause still matches.
_BUILTIN_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = tuple(
    (name, re.compile(regex, re.IGNORECASE))
    for name, regex in (
        # curl/wget with a local file as the request body
        ("curl-body-file",
         r"\bcurl\b[^|;&]*(?:--data(?:-binary|-raw|-urlencode)?|--form|-F|-d|-T)\b"
         r"[^|;&]*@\S+"),
        # scp / rsync to a remote destination (user@host:path)
        ("scp-out", r"\bscp\b[^|;&]*\S+\s+\w+@[\w.-]+:"),
        ("rsync-out", r"\brsync\b[^|;&]*\w+@[\w.-]+::?/\S*"),
        # local output piped into a network tool
        ("pipe-to-net", r"\|\s*(?:curl|wget|nc|netcat|openssl\s+s_client)\b"),
        # cloud-storage uploads of local paths
        ("cloud-upload",
         r"\b(?:gsutil|aws\s+s3|az\s+storage\s+blob)\b[^|;&]*\b(?:cp|copy|upload)\b"),
        # netcat / socat sending a file
        ("netcat-file", r"\b(?:nc|netcat|socat)\b[^|;&]*[<]\s*\S+"),
    ))

# No arming roots are shipped: the built-in shapes are outbound transfers of local
# content, which are worth gating regardless of which directory they name. Operators
# NARROW the guard to their own trees via settings.roots (kept in local Hermes config —
# never baked here); an unset or empty list arms the guard everywhere.
DEFAULT_ROOTS: Tuple[str, ...] = ()


def _setting(key: str, default: Any = None) -> Any:
    """Read `plugins.entries.<PLUGIN_ID>.settings.<key>`; same path/precedence as the
    sibling plugin's _setting (no register-time ctx exists yet — read config directly).
    Read on every call so an edit applies without a restart. Never raises."""
    try:
        from hermes_cli.config import load_config_readonly
        entry = ((load_config_readonly() or {}).get("plugins") or {}).get("entries") or {}
        settings = (entry.get(PLUGIN_ID) or {}).get("settings") or {}
        value = settings.get(key)
        return default if value in (None, "") else value
    except Exception:
        return default


def _compile(name: str, regex: str) -> Optional[Tuple[str, re.Pattern]]:
    """One (name, compiled) pair, or None with a warning. A pattern that cannot compile
    must never take the guard down — it is dropped, loudly."""
    if not isinstance(name, str) or not name.strip():
        logger.warning("%s: dropping settings pattern with empty name", PLUGIN_ID)
        return None
    if not isinstance(regex, str) or not regex.strip():
        logger.warning("%s: dropping settings pattern %r with empty regex",
                       PLUGIN_ID, name)
        return None
    try:
        return name.strip(), re.compile(regex, re.IGNORECASE)
    except re.error as exc:
        logger.warning("%s: dropping settings pattern %r (invalid regex: %s)",
                       PLUGIN_ID, name, exc)
        return None


def _patterns() -> Tuple[Tuple[str, re.Pattern], ...]:
    """Built-in shapes plus `settings.patterns`. Rebuilt per call: an edit applies without
    a restart. Invalid entries are dropped; the built-ins always remain."""
    extra_raw = _setting("patterns")
    extras: List[Tuple[str, re.Pattern]] = []
    if isinstance(extra_raw, list):
        for entry in extra_raw:
            if not isinstance(entry, dict):
                logger.warning("%s: dropping non-mapping settings pattern entry", PLUGIN_ID)
                continue
            compiled = _compile(str(entry.get("name", "")), str(entry.get("regex", "")))
            if compiled is not None:
                extras.append(compiled)
    return _BUILTIN_PATTERNS + tuple(extras)


def _roots() -> Tuple[str, ...]:
    """Arming prefixes. Each configured entry matches in BOTH spellings — the ~-literal
    form agents write (`~/matters/...`) and its expanded form (`/home/…`). Unset or empty
    means the guard arms EVERYWHERE: the shapes are outbound transfers of local content,
    risky regardless of directory. Operators narrow the guard to their own matter trees
    via settings.roots (local config — this repo ships no paths)."""
    raw = _setting("roots", DEFAULT_ROOTS)
    if not isinstance(raw, list):
        raw = DEFAULT_ROOTS
    out = []
    for entry in raw:
        if not isinstance(entry, str) or not entry.strip():
            continue
        text = entry.strip().rstrip("/")
        if not text:
            continue
        out.append(text)
        expanded = os.path.expanduser(text)
        if expanded != text:
            out.append(expanded)
    return tuple(out)


def _armed(command: str, roots: Tuple[str, ...]) -> bool:
    """True when the command text touches at least one arming root, or when no roots are
    configured (pattern match alone escalates)."""
    if not roots:
        return True
    return any(root in command for root in roots)


def guard_tool_call(tool_name: str = "", args: Optional[Dict[str, Any]] = None, **_: Any):
    """pre_tool_call callback: escalate legal-egress-shaped terminal commands.

    Returns None for everything else — observer semantics, no gating added. The directive
    is always `approve` (forces the existing human gate); `block` is deliberately never
    returned, and there is no code path here that lets a command run ungated.
    """
    try:
        if tool_name != "terminal":
            return None
        if _setting("enabled", True) is False:
            return None
        command = ""
        if isinstance(args, dict):
            command = str(args.get("command") or "")
        if not command.strip():
            return None
        roots = _roots()
        if not _armed(command, roots):
            return None
        for name, pattern in _patterns():
            if pattern.search(command):
                logger.info("%s: escalating %r command (matched %s)",
                            PLUGIN_ID, name, command[:80])
                return {
                    "action": "approve",
                    "message": (f"jev-approvals-guard: command matches the local egress "
                                f"shape '{name}' and is escalated for review."),
                    "rule_key": f"{PLUGIN_ID}:{name}",
                }
        return None
    except Exception:  # the hook runner fails closed on raise anyway; stay quiet
        logger.exception("%s: guard callback raised (hook runner will fail closed)",
                         PLUGIN_ID)
        return None


def register(ctx) -> None:
    """Register the pre_tool_call guard. `kind: standalone` is what makes this run — the
    model-provider kind this repo's plugin/ uses never gets register(ctx)."""
    ctx.register_hook("pre_tool_call", guard_tool_call)
