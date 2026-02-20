"""
feature_builder.py — Noise Reduction + Feature Extraction Layer
================================================================
Stage 1 of the AI Engine pipeline.

Responsibilities:
  1. Noise Reduction : drop rule.level < 5, deduplicate identical alerts
  2. Feature Extraction per agent over a sliding 5-minute window:
       failed_logins      – authentication failure rule IDs
       unique_source_ips  – distinct source IPs observed
       sudo_events        – privilege escalation rule IDs
       file_modifications – syscheck (FIM) group events
       process_creations  – process_monitor group events

Returns a list of dicts ready for the Isolation Forest model.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

# ── Rule ID sets ──────────────────────────────────────────────────────────────
FAILED_LOGIN_RULES: frozenset[int] = frozenset({5710, 5711, 5712, 5713, 18152})
SUDO_RULES:         frozenset[int] = frozenset({5401, 5402, 5403})
SYSCHECK_GROUPS:    frozenset[str] = frozenset({"syscheck"})
PROCESS_GROUPS:     frozenset[str] = frozenset({"process_monitor", "ossec"})

MIN_RULE_LEVEL = 5

# Feature vector column order — MUST stay consistent for the model
FEATURE_NAMES = ["failed_logins", "unique_ips", "sudo", "file_mods", "process", "threats"]
N_FEATURES    = len(FEATURE_NAMES)


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
    Given events for a single agent, return a feature dict.
    Broader logic using rule groups and MITRE data.
    """
    failed_logins = 0
    source_ips: set[str] = set()
    ip_counts:  dict[str, int] = {}
    sudo_events = 0
    file_mods   = 0
    processes   = 0
    threats     = 0

    for e in events:
        rid     = e.get("rule_id", 0)
        # Groups is a frozenset, but let's be safe
        rgroups = e.get("rule_groups", frozenset())
        sip     = e.get("src_ip")
        
        # Check rule groups for broader categorization
        if "authentication_failed" in rgroups or "login_denied" in rgroups or "authentication_failures" in rgroups:
            failed_logins += 1
            
        if sip and sip != "-" and sip != "0.0.0.0":
            source_ips.add(sip)
            ip_counts[sip] = ip_counts.get(sip, 0) + 1

        if "sudo" in rgroups or "pam" in rgroups:
            sudo_events += 1

        if "syscheck" in rgroups or "fim" in rgroups:
            file_mods += 1

        if "process_monitor" in rgroups or "ossec" in rgroups:
            processes += 1
            
        # Generic threat counter (high level or specific attack groups)
        if "attack" in rgroups or "exploit" in rgroups or e.get("rule_level", 0) >= 10:
            threats += 1

    top_ip = max(ip_counts, key=ip_counts.get) if ip_counts else None

    return {
        "failed_logins":  failed_logins,
        "unique_ips":     len(source_ips),
        "sudo":           sudo_events,
        "file_mods":      file_mods,
        "process":        processes,
        "threats":        threats,
        "top_source_ip":  top_ip,
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
            "feature_vector": [int, int, int, int, int],  # FEATURE_NAMES order
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
                        # Use .keyword for exact-match on text fields
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
