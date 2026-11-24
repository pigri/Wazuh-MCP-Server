"""
Wazuh 5.x support: index names, field names and document normalization.

Wazuh 5.0 changed where the data lives:

- Alerts are Security Analytics findings in ``wazuh-findings-v5-*`` (there is no
  ``wazuh-alerts-*``). Rule levels are Sigma keywords (informational, low, medium, high,
  critical), rule ids are UUIDs, the rule, agent and compliance data sit under ``wazuh.*``
  and the timestamp is ``@timestamp``.
- Agent inventory (processes, ports), SCA results and the FIM file inventory are state
  indices (``wazuh-states-*``); the Server API endpoints ``/syscollector``, ``/sca`` and
  ``/syscheck`` are gone.
- ``/manager/*``, ``/rules``, ``/decoders``, ``/lists`` and ``/active-response`` are gone
  from the Server API. Manager logs and daemon statistics are per cluster node
  (``/cluster/{node_id}/logs``, ``/cluster/{node_id}/daemons/stats``); rules are content
  in ``wazuh-threatintel-rules-*``.
- Vulnerability states are in ``wazuh-states-vulnerabilities`` (no suffix) with the agent
  under ``wazuh.agent``.

The tools keep the 4.x response shapes: queries use the 5.x names and documents are
normalized back into 4.x-shaped alerts and items here.
"""

from typing import Any, Dict, Iterable, List, Optional

FINDINGS_INDEX = "wazuh-findings-v5-*"
EVENTS_INDEX = "wazuh-events-v5-*"
RULES_INDEX = "wazuh-threatintel-rules-*"
PROCESSES_INDEX = "wazuh-states-inventory-processes*"
PORTS_INDEX = "wazuh-states-inventory-ports*"
SCA_INDEX = "wazuh-states-sca*"
FIM_INDEX = "wazuh-states-fim-files*"

# Rule spaces whose rules are loaded by the engine (draft and test are work in progress).
ACTIVE_RULE_SPACES = ["standard", "custom"]

# 5.x levels are Sigma keywords; 4.x levels were 0-15. These equivalents keep numeric
# thresholds ("level >= 10"), level grouping and level-based scoring meaningful.
LEVEL_NUMBER: Dict[str, int] = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 15}

# 4.x alert field -> 5.x finding field, for queries and aggregations.
ALERT_FIELDS: Dict[str, str] = {
    "rule.id": "wazuh.rule.id",
    "rule.level": "wazuh.rule.level",
    "rule.groups": "wazuh.rule.tags",
    "rule.description": "wazuh.rule.title",
    "agent.id": "wazuh.agent.id",
    "agent.name": "wazuh.agent.name",
    "timestamp": "@timestamp",
    "data.srcip": "source.ip",
    "data.dstip": "destination.ip",
    "syscheck.path": "file.path",
    "syscheck.event": "event.action",
}

# 4.x syscheck.event -> 5.x FIM finding event.action.
FIM_EVENT_TO_V5: Dict[str, str] = {"added": "created", "modified": "modified", "deleted": "deleted"}
FIM_EVENT_FROM_V5: Dict[str, str] = {v: k for k, v in FIM_EVENT_TO_V5.items()}

# GET /agents select fields accepted by the 5.0 Server API (others answer HTTP 400,
# e.g. node_name, configSum, mergedSum).
AGENT_SELECT_FIELDS = frozenset(
    {
        "dateAdd",
        "disconnection_time",
        "group",
        "id",
        "ip",
        "lastKeepAlive",
        "name",
        "os.arch",
        "os.major",
        "os.minor",
        "os.name",
        "os.platform",
        "os.type",
        "os.version",
        "registerIP",
        "status",
        "status_code",
        "version",
    }
)


# Free-text search on findings. The 5.x index template limits index.query.default_field to
# a few wazuh.agent.* fields, so a query without fields matches almost nothing: name them.
SEARCH_FIELDS: List[str] = [
    "message",
    "wazuh.rule.title",
    "rule.name",
    "event.original",
    "source.ip",
    "destination.ip",
    "user.name",
    "file.path",
    "process.name",
    "process.command_line",
    "host.hostname",
    "wazuh.agent.name",
    "url.original",
    "dns.question.name",
]
# message and the rule title are keyword fields (no full-text analysis): plain words in the
# query are also matched as case-insensitive substrings of these two, a bounded number of them.
SUBSTRING_FIELDS: List[str] = ["message", "wazuh.rule.title"]
_MAX_SUBSTRING_TERMS = 5


def substring_terms(query: str) -> List[str]:
    """Plain words of a free-text query for substring matching (no operators, quotes or
    wildcards; at least 3 characters; at most 5)."""
    if any(c in query for c in '"()|+*?\\~'):
        return []
    words = [w for w in query.split() if w.upper() not in ("AND", "OR", "NOT") and not w.startswith("-")]
    words = [w for w in words if len(w) >= 3]
    return words[:_MAX_SUBSTRING_TERMS]


def substring_query(terms: List[str]) -> Dict[str, Any]:
    """Every term must occur (case-insensitive) in message or the rule title."""
    return {
        "bool": {
            "must": [
                {
                    "bool": {
                        "should": [
                            {"wildcard": {f: {"value": f"*{t}*", "case_insensitive": True}}} for f in SUBSTRING_FIELDS
                        ],
                        "minimum_should_match": 1,
                    }
                }
                for t in terms
            ]
        }
    }


def alert_field(name: str) -> str:
    """5.x finding field for a 4.x alert field (unchanged when there is no mapping)."""
    return ALERT_FIELDS.get(name, name)


def level_number(level: Any) -> int:
    """Numeric (4.x-scale) level of a 5.x level keyword; numbers pass through."""
    if isinstance(level, bool):
        return 0
    if isinstance(level, (int, float)):
        return int(level)
    return LEVEL_NUMBER.get(str(level or "").strip().lower(), 0)


def levels_at_least(min_level: int) -> List[str]:
    """5.x level keywords whose numeric equivalent is >= min_level."""
    return [k for k, v in LEVEL_NUMBER.items() if v >= min_level]


def agent_select(select: Any) -> Optional[str]:
    """Keep only the /agents select fields 5.x accepts; None when nothing is left."""
    if select is None:
        return None
    fields = select if isinstance(select, (list, tuple)) else str(select).split(",")
    kept = [f.strip() for f in fields if f.strip() in AGENT_SELECT_FIELDS]
    return ",".join(dict.fromkeys(kept)) or None


def _first(value: Any) -> Any:
    """First element of a list value (ECS ip fields are arrays in the state indices)."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _unique(values: Iterable[Any]) -> List[Any]:
    return list(dict.fromkeys(v for v in values if v not in (None, "")))


def agent_of(src: Dict[str, Any]) -> Dict[str, Any]:
    """{"id", "name"} of the agent a 5.x document belongs to."""
    wa = (src.get("wazuh") or {}).get("agent") or {}
    return {"id": wa.get("id"), "name": wa.get("name")}


def normalize_finding(src: Dict[str, Any]) -> Dict[str, Any]:
    """A 5.x finding in the 4.x alert shape (rule.*, agent.*, timestamp, data.*, syscheck.*).

    The finding's own fields are kept; ``rule`` is replaced by the Wazuh rule (the
    source's own rule, e.g. an IDS signature, moves to ``rule.event_rule``).
    """
    src = src or {}
    wazuh = src.get("wazuh") or {}
    wr = wazuh.get("rule") or {}
    event = src.get("event") or {}
    integration = (wazuh.get("integration") or {}).get("name")
    categories = event.get("category") or []
    if isinstance(categories, str):
        categories = [categories]

    rule: Dict[str, Any] = {
        "id": wr.get("id"),
        "level": level_number(wr.get("level")),
        "severity": wr.get("level"),
        "description": wr.get("title") or (src.get("rule") or {}).get("name") or src.get("message"),
        "groups": _unique(list(wr.get("tags") or []) + list(categories) + [integration]),
        "status": wr.get("status"),
    }
    mitre = wr.get("mitre") or {}
    if mitre:
        technique = mitre.get("technique") or {}
        tactic = mitre.get("tactic") or {}
        rule["mitre"] = {
            "id": technique.get("id") or [],
            "technique": technique.get("name") or [],
            "tactic": tactic.get("name") or [],
        }
    for framework, controls in (wr.get("compliance") or {}).items():
        rule[framework] = controls
    if src.get("rule"):
        rule["event_rule"] = src["rule"]

    out = dict(src)
    out["rule"] = rule
    out["agent"] = {**(src.get("agent") or {}), **agent_of(src)}
    out["timestamp"] = src.get("@timestamp")

    data = dict(src.get("data") or {}) if isinstance(src.get("data"), dict) else {}
    source = src.get("source") or {}
    destination = src.get("destination") or {}
    for key, value in (
        ("srcip", _first(source.get("ip"))),
        ("srcport", source.get("port")),
        ("dstip", _first(destination.get("ip"))),
        ("dstport", destination.get("port")),
        ("srcuser", (src.get("user") or {}).get("name")),
    ):
        if value is not None:
            data.setdefault(key, value)
    out["data"] = data

    if event.get("original") is not None:
        out.setdefault("full_log", event.get("original"))

    file = src.get("file") or {}
    if integration == "wazuh-fim" or (event.get("dataset") == "wazuh.fim"):
        hashes = file.get("hash") or {}
        out["syscheck"] = {
            "path": file.get("path"),
            "event": FIM_EVENT_FROM_V5.get(event.get("action"), event.get("action")),
            "size_after": file.get("size"),
            "md5_after": hashes.get("md5"),
            "sha1_after": hashes.get("sha1"),
            "sha256_after": hashes.get("sha256"),
            "uname_after": file.get("owner"),
            "gname_after": file.get("group"),
            "mtime_after": file.get("mtime"),
        }
    return out


def _scan(src: Dict[str, Any]) -> Dict[str, Any]:
    return {"time": (src.get("state") or {}).get("modified_at")}


def process_item(src: Dict[str, Any]) -> Dict[str, Any]:
    """A wazuh-states-inventory-processes document as a 4.x syscollector process."""
    p = src.get("process") or {}
    return {
        "agent_id": agent_of(src)["id"],
        "pid": p.get("pid"),
        "ppid": (p.get("parent") or {}).get("pid"),
        "name": p.get("name"),
        "state": p.get("state"),
        "cmd": p.get("command_line"),
        "argvs": p.get("args"),
        "start_time": p.get("start"),
        "utime": p.get("utime"),
        "stime": p.get("stime"),
        "euser": (src.get("user") or {}).get("name"),
        "scan": _scan(src),
    }


def port_item(src: Dict[str, Any]) -> Dict[str, Any]:
    """A wazuh-states-inventory-ports document as a 4.x syscollector port."""
    s = src.get("source") or {}
    d = src.get("destination") or {}
    p = src.get("process") or {}
    return {
        "agent_id": agent_of(src)["id"],
        "local": {"ip": _first(s.get("ip")), "port": s.get("port")},
        "remote": {"ip": _first(d.get("ip")), "port": d.get("port")},
        "protocol": (src.get("network") or {}).get("transport"),
        "state": (src.get("interface") or {}).get("state"),
        "process": p.get("name"),
        "pid": p.get("pid"),
        "inode": (src.get("file") or {}).get("inode"),
        "scan": _scan(src),
    }


def fim_item(src: Dict[str, Any]) -> Dict[str, Any]:
    """A wazuh-states-fim-files document as a 4.x syscheck entry."""
    f = src.get("file") or {}
    h = f.get("hash") or {}
    perm = f.get("permissions")
    return {
        "agent_id": agent_of(src)["id"],
        "file": f.get("path"),
        "type": "file",
        "size": f.get("size"),
        "perm": ",".join(perm) if isinstance(perm, list) else perm,
        "uid": f.get("uid"),
        "gid": f.get("gid"),
        "uname": f.get("owner"),
        "gname": f.get("group"),
        "inode": f.get("inode"),
        "mtime": f.get("mtime"),
        "md5": h.get("md5"),
        "sha1": h.get("sha1"),
        "sha256": h.get("sha256"),
        "date": (src.get("state") or {}).get("modified_at"),
    }


def sca_result(value: Any) -> str:
    """5.x check.result ("Passed", "Failed", "Not applicable") in 4.x form (lower case)."""
    return str(value or "").strip().lower()


def sca_check_item(src: Dict[str, Any]) -> Dict[str, Any]:
    """A wazuh-states-sca document as a 4.x SCA check."""
    c = src.get("check") or {}
    compliance = [
        {"key": k, "value": ",".join(v) if isinstance(v, list) else str(v)}
        for k, v in (c.get("compliance") or {}).items()
    ]
    return {
        "id": c.get("id"),
        "policy_id": (src.get("policy") or {}).get("id"),
        "title": c.get("name"),
        "description": c.get("description"),
        "rationale": c.get("rationale"),
        "remediation": c.get("remediation"),
        "result": sca_result(c.get("result")),
        "reason": c.get("reason"),
        "condition": c.get("condition"),
        "compliance": compliance,
        "rules": [{"rule": r} for r in (c.get("rules") or [])],
    }


def sca_policy_item(bucket: Dict[str, Any]) -> Dict[str, Any]:
    """One policy bucket of the SCA aggregation as a 4.x /sca/{agent_id} item."""
    results = {sca_result(b.get("key")): b.get("doc_count", 0) for b in bucket.get("results", {}).get("buckets", [])}
    hits = bucket.get("info", {}).get("hits", {}).get("hits", [])
    policy = ((hits[0].get("_source") or {}).get("policy") or {}) if hits else {}
    passed, failed = results.get("passed", 0), results.get("failed", 0)
    return {
        "policy_id": bucket.get("key"),
        "name": policy.get("name"),
        "description": policy.get("description"),
        "references": policy.get("references"),
        "pass": passed,
        "fail": failed,
        "invalid": results.get("not applicable", 0),
        "total_checks": bucket.get("doc_count", 0),
        "score": round(100 * passed / (passed + failed)) if passed + failed else 0,
        "end_scan": (bucket.get("last") or {}).get("value_as_string"),
    }


def rule_item(src: Dict[str, Any]) -> Dict[str, Any]:
    """A wazuh-threatintel-rules document as a 4.x /rules item."""
    d = src.get("document") or {}
    meta = d.get("metadata") or {}
    return {
        "id": d.get("id"),
        "level": level_number(d.get("level")),
        "severity": d.get("level"),
        "description": meta.get("title") or d.get("title"),
        "groups": list(d.get("tags") or []),
        "status": d.get("status"),
        "space": (src.get("space") or {}).get("name"),
    }


def wazuh_items(items: List[Dict[str, Any]], total: Optional[int] = None) -> Dict[str, Any]:
    """Wrap items in the Server API response envelope the tools expect."""
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": len(items) if total is None else total,
            "total_failed_items": 0,
            "failed_items": [],
        },
        "error": 0,
    }
