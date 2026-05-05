"""
feature_builder.py — Noise Reduction + Feature Extraction Layer
================================================================
Stage 1 of the AI Engine pipeline.

Responsibilities:
  1. Noise Reduction : drop rule.level < 5, deduplicate identical alerts
  2. Feature Extraction per agent over a sliding 5-minute window:
       failed_logins      – authentication failure / invalid user events
       brute_force        – rapid repeated failures (frequency rules 100001, 100004)
       unique_ips         – distinct source IPs observed
       sudo               – privilege escalation rule groups + rule IDs 100010-100011
       file_mods          – syscheck (FIM) group events
       web_attacks        – SQLi, XSS, LFI, CMDi (rules 100030-100034)
       lateral            – recon, port-scan, tunnel (rules 100050-100051)
       persistence        – cron/SSH-key/service/shell-init mods (rules 100020-100023)
       process            – process_monitor / execution anomalies (rules 100070-100072)
       threats            – any event with rule.level >= 10

Returns a list of dicts ready for the Isolation Forest model.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# ── Rule ID sets ──────────────────────────────────────────────────────────────
# Default Wazuh SSH rules
SSH_FAILURE_RULES: frozenset[int] = frozenset({5710, 5711, 5712, 5713, 5716, 18152})
# Custom SENTINEL brute-force correlation rules
BRUTE_FORCE_RULES: frozenset[int] = frozenset({100001, 100002, 100004, 100005, 100080, 100081})
# Custom SENTINEL web attack rules
WEB_ATTACK_RULES:  frozenset[int] = frozenset({100030, 100031, 100032, 100033, 100034})
# Custom SENTINEL privilege escalation rules
SUDO_RULES:        frozenset[int] = frozenset({5401, 5402, 5403, 100010, 100011, 100012, 100013})
# Custom SENTINEL persistence rules
PERSIST_RULES:     frozenset[int] = frozenset({100020, 100021, 100022, 100023, 100041})
# Custom SENTINEL lateral movement / recon rules
LATERAL_RULES:     frozenset[int] = frozenset({100050, 100051, 100060, 100061})
# Syscheck / FIM groups
SYSCHECK_GROUPS:   frozenset[str] = frozenset({"syscheck", "fim"})
# Process monitor groups
PROCESS_GROUPS:    frozenset[str] = frozenset({"process_monitor", "execution"})

MIN_RULE_LEVEL = 5

# Feature vector column order — MUST stay consistent for the model
# NOTE: Adding new features here requires wiping /shared_data/model.pkl
#       so the model is retrained on the new shape.
FEATURE_NAMES = [
    "failed_logins",   # SSH/PAM auth failures
    "brute_force",     # Frequency-based brute-force correlation
    "unique_ips",      # Distinct source IPs
    "sudo",            # Privilege escalation events
    "file_mods",       # FIM / syscheck changes
    "web_attacks",     # SQLi, XSS, LFI, CMDi
    "lateral",         # Recon, port-scan, tunneling, firewall mod
    "persistence",     # Cron/SSH-key/service/shell-init persistence
    "process",         # Suspicious process / execution events
    "threats",         # Any high-level (>=10) event
]
N_FEATURES = len(FEATURE_NAMES)


# ── Query builder ─────────────────────────────────────────────────────────────

def _build_time_range_query(window_minutes: int) -> dict:
    """OpenSearch query for the last N minutes with rule.level >= MIN_RULE_LEVEL."""
    since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    return {
        "size": 5000,
        "_source": [
            "agent.name",
            "rule.id",
            "rule.level",
            "rule.groups",
            "data.srcip",
            "@timestamp",
            "full_log",
        ],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": since.strftime("%Y-%m-%dT%H:%M:%SZ")}}},
                    {"range": {"rule.level": {"gte": MIN_RULE_LEVEL}}},
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
    }


# ── Hit parser ────────────────────────────────────────────────────────────────

def _parse_hit(hit: dict) -> dict | None:
    """
    Extract relevant fields from a raw OpenSearch hit.
    Returns None if the hit is malformed or missing agent name.
    """
    try:
        src = hit.get("_source") or {}
        agent_name = (src.get("agent") or {}).get("name", "").strip()
        if not agent_name:
            return None

        rule = src.get("rule") or {}
        try:
            rule_id = int(rule.get("id") or 0)
        except (ValueError, TypeError):
            rule_id = 0

        # rule.groups may come as a list or a single string
        raw_groups = rule.get("groups") or []
        if isinstance(raw_groups, str):
            raw_groups = [raw_groups]
        rule_groups: frozenset[str] = frozenset(raw_groups)

        src_ip   = str((src.get("data") or {}).get("srcip") or "").strip()
        full_log = str(src.get("full_log") or "")

        return {
            "agent":       agent_name,
            "rule_id":     rule_id,
            "rule_groups": rule_groups,
            "rule_level":  int(rule.get("level") or 0),
            "src_ip":      src_ip,
            "full_log":    full_log,
        }
    except Exception:
        return None


# ── Deduplication ─────────────────────────────────────────────────────────────

def _deduplicate(events: list[dict]) -> list[dict]:
    """
    Remove duplicate alerts: same (agent, rule_id, log_prefix).
    Keeps the first occurrence only.
    """
    seen: set[tuple] = set()
    unique: list[dict] = []
    for e in events:
        key = (e["agent"], e["rule_id"], e["full_log"][:120])
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique


# ── Per-agent feature extraction ──────────────────────────────────────────────

def _extract_features_for_agent(events: list[dict]) -> dict:
    """
    Given events for a single agent, return a 10-dimensional feature dict
    aligned with FEATURE_NAMES.

    Each counter maps to one detected attack category:
      failed_logins  → SSH/PAM auth failure events
      brute_force    → Wazuh frequency-rule brute-force correlations (100001, 100004)
      unique_ips     → Distinct source IPs (breadth of origin)
      sudo           → sudo / privilege escalation events
      file_mods      → FIM / syscheck file change events
      web_attacks    → Web attack rule hits (SQLi, XSS, LFI, CMDi)
      lateral        → Recon / lateral movement rule hits
      persistence    → Persistence mechanism rule hits
      process        → Suspicious process / execution events
      threats        → Any event with rule.level >= 10 (catch-all high severity)
    """
    failed_logins = 0
    brute_force   = 0
    sudo_events   = 0
    file_mods     = 0
    web_attacks   = 0
    lateral       = 0
    persistence   = 0
    processes     = 0
    threats       = 0

    source_ips: set[str] = set()
    ip_counts:  dict[str, int] = {}

    for e in events:
        rid     = e.get("rule_id", 0)
        rgroups = e.get("rule_groups", frozenset())
        level   = e.get("rule_level", 0)
        sip     = e.get("src_ip", "")

        # ── Source IP tracking ────────────────────────────────────────────────
        if sip and sip not in ("-", "0.0.0.0", ""):
            source_ips.add(sip)
            ip_counts[sip] = ip_counts.get(sip, 0) + 1

        # ── Failed logins ─────────────────────────────────────────────────────
        if (rid in SSH_FAILURE_RULES
                or "authentication_failed" in rgroups
                or "authentication_failures" in rgroups
                or "login_denied" in rgroups):
            failed_logins += 1

        # ── Brute-force correlations ──────────────────────────────────────────
        if (rid in BRUTE_FORCE_RULES
                or "brute_force" in rgroups):
            brute_force += 1

        # ── Sudo / privilege escalation ───────────────────────────────────────
        if (rid in SUDO_RULES
                or "sudo" in rgroups
                or "pam" in rgroups
                or "privilege_escalation" in rgroups):
            sudo_events += 1

        # ── File integrity (FIM) ──────────────────────────────────────────────
        if ("syscheck" in rgroups
                or "fim" in rgroups
                or rid in {100020, 100021, 100022, 100023, 100040, 100041, 100042}):
            file_mods += 1

        # ── Web attacks ───────────────────────────────────────────────────────
        if (rid in WEB_ATTACK_RULES
                or "web" in rgroups
                or "sql_injection" in rgroups
                or "xss" in rgroups
                or "command_injection" in rgroups):
            web_attacks += 1

        # ── Lateral movement / recon ──────────────────────────────────────────
        if (rid in LATERAL_RULES
                or "recon" in rgroups
                or "lateral_movement" in rgroups
                or "firewall" in rgroups):
            lateral += 1

        # ── Persistence ───────────────────────────────────────────────────────
        if (rid in PERSIST_RULES
                or "persistence" in rgroups
                or "adduser" in rgroups):
            persistence += 1

        # ── Process / execution anomalies ─────────────────────────────────────
        if ("process_monitor" in rgroups
                or "execution" in rgroups
                or "ossec" in rgroups
                or rid in {100070, 100071, 100072}):
            processes += 1

        # ── High-severity catch-all ───────────────────────────────────────────
        if ("attack" in rgroups
                or "exploit" in rgroups
                or level >= 10):
            threats += 1

    top_ip = max(ip_counts, key=ip_counts.get) if ip_counts else None

    return {
        "failed_logins": failed_logins,
        "brute_force":   brute_force,
        "unique_ips":    len(source_ips),
        "sudo":          sudo_events,
        "file_mods":     file_mods,
        "web_attacks":   web_attacks,
        "lateral":       lateral,
        "persistence":   persistence,
        "process":       processes,
        "threats":       threats,
        "top_source_ip": top_ip,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def build_features(client, window_minutes: int = 5) -> list[dict]:
    """
    Main entry point.

    Query → Parse → Noise-reduce → Feature-extract per agent.

    Returns:
        [
          {
            "agent":          "hostname",
            "feature_vector": [int, ...],  # FEATURE_NAMES order (10 values)
            "features":       {"failed_logins": int, ...}
          },
          ...
        ]

    Raises: propagated so caller can enter DEGRADED state.
    """
    query    = _build_time_range_query(window_minutes)
    response = client.search(index="wazuh-alerts-*", body=query)
    hits     = (response.get("hits") or {}).get("hits") or []

    logger.info("[FeatureBuilder] Raw hits: %d", len(hits))

    # Parse
    parsed: list[dict] = []
    for hit in hits:
        e = _parse_hit(hit)
        if e is not None:
            parsed.append(e)

    # Deduplicate
    deduped = _deduplicate(parsed)
    logger.info("[FeatureBuilder] After dedup: %d events", len(deduped))

    # Group by agent
    agent_events: dict[str, list[dict]] = {}
    for e in deduped:
        agent_events.setdefault(e["agent"], []).append(e)

    # Extract per-agent
    results: list[dict] = []
    for agent_name, evs in agent_events.items():
        feat_dict   = _extract_features_for_agent(evs)
        feat_vector = [feat_dict[k] for k in FEATURE_NAMES]
        results.append({
            "agent":          agent_name,
            "feature_vector": feat_vector,
            "features":       feat_dict,
        })

    logger.info("[FeatureBuilder] Feature vectors built for %d agents", len(results))
    return results


def discover_agents(client) -> list[str]:
    """
    Discover known agent names from the last 24 h of alerts.
    Falls back gracefully to empty list on error.
    """
    try:
        query = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
            "aggs": {
                "agents": {
                    "terms": {
                        "field": "agent.name",
                        "size":  100,
                    }
                }
            },
        }
        resp    = client.search(index="wazuh-alerts-*", body=query)
        buckets = ((resp.get("aggregations") or {}).get("agents") or {}).get("buckets") or []
        return [b["key"] for b in buckets if b.get("key")]
    except Exception as exc:
        logger.warning("[FeatureBuilder] discover_agents failed: %s", exc)
        return []


def zero_vector_entry(agent_name: str) -> dict:
    """Return a zeroed feature entry for a known but silent agent."""
    return {
        "agent":          agent_name,
        "feature_vector": [0] * N_FEATURES,
        "features":       {k: 0 for k in FEATURE_NAMES},
    }
