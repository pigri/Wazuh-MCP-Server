# Wazuh Compatibility

Which Wazuh versions this server works with, which Wazuh APIs it calls, and what each needs.

## Supported versions

| Wazuh version | Status |
|---|---|
| 5.0 | Supported (checked against 5.0.0-rc2). The Wazuh Indexer is required for more tools than on 4.x; see [Wazuh 5.x](#wazuh-5x). Weekly statistics and the active-response write tools are not available. |
| 4.8.0 – 4.14.7 | Supported. The Wazuh Indexer is required for alert, vulnerability and alert-backed compliance tools. |
| 4.0 – 4.7 | Not supported. Vulnerability data lives in the Manager API on these versions, and this server only reads it from the Indexer. |
| < 4.0 | Not supported. |

What has been checked:

- Every Manager API endpoint the server calls (listed below) is present in the published Wazuh
  API specifications for **4.13.0, 4.14.0, 4.14.1 and 4.14.7**, with the same RBAC actions.
- Active-response behavior (delivery semantics, per-command timeout handling) was checked
  against the Wazuh 4.14 source.
- Versions 4.8 – 4.12 are in the supported range but were not re-checked against their API
  specifications for this document.

## Wazuh 5.x

Wazuh 5.0 moved most of the data the 4.x Server API served into the Indexer and removed those
endpoints. The server reads the version from `GET /` (`data.api_version`) on first use, or from
`WAZUH_MAJOR_VERSION` when set, and on 5.x maps each 4.x call; tools keep their 4.x response
shapes. The mapping lives in `src/wazuh_mcp_server/api/wazuh5.py` and `WazuhClient._route_v5`.

| 4.x source | 5.x source | Tools |
|---|---|---|
| `wazuh-alerts-*` | `wazuh-findings-v5-*` (Security Analytics findings) | Alert search, summaries, aggregations, threat, IoC, risk, report and ISO 27001 alert evidence |
| `wazuh-states-vulnerabilities-*` | `wazuh-states-vulnerabilities` (agent under `wazuh.agent`) | Vulnerability tools |
| `GET /syscollector/{agent_id}/processes`, `/ports` | `wazuh-states-inventory-processes`, `wazuh-states-inventory-ports` | `get_agent_processes`, `get_agent_ports`, `wazuh_check_process` |
| `GET /syscheck/{agent_id}` | `wazuh-states-fim-files` | `wazuh_check_file_quarantine` |
| `GET /sca/{agent_id}`, `/sca/{agent_id}/checks/{policy_id}` | `wazuh-states-sca` (pass/fail counts aggregated per policy) | SCA, compliance, risk and ISO 27001 tools |
| `GET /rules` | `wazuh-threatintel-rules-*` (enabled rules of the `standard` and `custom` spaces) | `get_wazuh_rules_summary` |
| `GET /manager/logs` | `GET /cluster/{node_id}/logs` | Manager log tools |
| `GET /manager/stats`, `/manager/stats/remoted` | `GET /cluster/{node_id}/daemons/stats` | Statistics tools |
| `GET /manager/stats/analysisd` | analysisd daemon stats, plus the number of events in `wazuh-events-v5-*` over 24 hours as `total_events_decoded` | `get_wazuh_log_collector_stats`, ISO 27001 logging evidence |
| `PUT /manager/restart` | `PUT /cluster/restart?nodes_list=<node>` | `wazuh_restart` with `target=manager` |
| `GET /manager/stats/weekly` | none | `get_wazuh_weekly_stats` reports that 5.x has no equivalent |
| `PUT /active-response` | none in the Server API | Active-response write tools report that 5.x has no API for them (5.x runs active responses from Alerting monitors on findings, configured in the dashboard) |

Differences to expect on 5.x:

- **Rule levels** are Sigma keywords. Alerts report `rule.level` as a 4.x-scale number
  (informational 3, low 5, medium 8, high 12, critical 15) and the keyword as `rule.severity`;
  a `level` filter of `10` matches high and critical.
- **Rule ids** are UUIDs, `rule.description` is the rule title, and `rule.groups` holds the rule
  tags, the event categories and the integration name. The finding's own `rule` (for example an
  IDS signature) is kept as `rule.event_rule`; compliance mappings are `rule.<framework>`.
- **Free-text search** names the fields it searches (the 5.x index template limits the default
  fields to a few `wazuh.agent.*` fields) and also matches up to five plain words as
  case-insensitive substrings of the message and rule title, because those are keyword fields.
- `GET /agents` no longer accepts `node_name`, `configSum` or `mergedSum` in `select`; the server
  drops them.

Indexer account on 5.x: search access to `wazuh-findings-v5-*`, `wazuh-events-v5-*`,
`wazuh-states-*` and `wazuh-threatintel-rules-*` (or `wazuh-*`). Manager API account on 5.x:
`agent:read`, `group:read`, `cluster:read` (and `agent:restart`, `cluster:restart` for the
restart tool); the `sca:read`, `syscheck:read`, `syscollector:read`, `rules:read` and
`manager:read` actions no longer exist.

## Where data comes from

| Source | Setting | Data |
|---|---|---|
| Manager REST API (default port 55000) | `WAZUH_HOST`, `WAZUH_PORT`, `WAZUH_USER`, `WAZUH_PASS` | Agents, syscollector (processes, ports), FIM (syscheck), SCA, rules, manager logs and statistics, cluster, active response, restarts |
| Wazuh Indexer (default port 9200) | `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_PORT`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` | Alerts (`wazuh-alerts-*`) and vulnerability state (`wazuh-states-vulnerabilities-*`) |

The Manager API has no alerts or vulnerability endpoints in 4.13 and 4.14 (none in the specs),
so alert search, alert aggregation, vulnerability tools and the alert-backed parts of the
compliance and ISO 27001 tools need the Indexer. Without `WAZUH_INDEXER_HOST` those tools
return an "Indexer not configured" error instead of empty results.

## Manager API endpoints used

From `src/wazuh_mcp_server/api/wazuh_client.py`. RBAC actions are the `x-rbac-actions` values
from the Wazuh API specification; use them to build a least-privilege API user (see
[docs/security/README.md](docs/security/README.md#least-privilege-wazuh-accounts)).

| Method and path | RBAC action | Used for |
|---|---|---|
| `POST /security/user/authenticate` | none | Exchanging `WAZUH_USER`/`WAZUH_PASS` for a Wazuh JWT |
| `GET /` | none | Manager info, connection validation, `/ready` probe |
| `GET /agents` | `agent:read` | Agent listing and status; resolving active agents for SCA and risk tools |
| `GET /groups/{group_id}/configuration` | `group:read` | `get_agent_configuration` |
| `GET /syscollector/{agent_id}/processes` | `syscollector:read` | `get_agent_processes`, `wazuh_check_process` |
| `GET /syscollector/{agent_id}/ports` | `syscollector:read` | `get_agent_ports` |
| `GET /syscheck/{agent_id}` | `syscheck:read` | `wazuh_check_file_quarantine` |
| `GET /sca/{agent_id}` | `sca:read` | `run_compliance_check`, `perform_risk_assessment`, `generate_security_report`, ISO 27001 dashboard and control detail |
| `GET /sca/{agent_id}/checks/{policy_id}` | `sca:read` | `get_sca_policy_checks` |
| `GET /rules` | `rules:read` | `get_wazuh_rules_summary` |
| `GET /manager/logs` | `manager:read` | `search_wazuh_manager_logs`, `get_wazuh_manager_error_logs` (`limit` up to 500) |
| `GET /manager/stats` | `manager:read` | `get_wazuh_statistics` |
| `GET /manager/stats/weekly` | `manager:read` | `get_wazuh_weekly_stats` |
| `GET /manager/stats/analysisd` | `manager:read` | `get_wazuh_log_collector_stats`, ISO 27001 dashboard and control detail (deprecated, see below) |
| `GET /manager/stats/remoted` | `manager:read` | `get_wazuh_remoted_stats` (deprecated, see below) |
| `GET /cluster/healthcheck` | `cluster:read` | `get_wazuh_cluster_health` |
| `GET /cluster/nodes` | `cluster:read` | `get_wazuh_cluster_nodes` |
| `PUT /active-response` | `active-response:command` | Active-response write tools |
| `PUT /agents/{agent_id}/restart` | `agent:restart` | `wazuh_restart` on an agent |
| `PUT /manager/restart` | `manager:read`, `manager:restart` | `wazuh_restart` with `target=manager` (or `000`); needs `WAZUH_ALLOW_MANAGER_AR=true` |

`wazuh_client.py` also contains helpers for `GET /cluster/status`, `/decoders`, `/lists`,
`/manager/configuration` and `/agents/{agent_id}/stats/{component}`; no tool calls them.

### Deprecated endpoints

`GET /manager/stats/analysisd` and `GET /manager/stats/remoted` are marked `deprecated: true`
in the 4.13.0 and 4.14.x specifications. They still respond in those versions. The
specification also defines `GET /manager/daemons/stats`; the server does not use it yet. If a
future Wazuh release removes the deprecated endpoints, the tools listed against them above
will fail.

### Active response request body

The 4.14 `ActiveResponseBody` schema accepts `command`, `arguments` and `alert.data`; target
agents go in the `agents_list` query parameter. The server builds the request that way and
strips a `custom` key from the body if a caller supplies one. Commands
dispatched through the API run as `!`-prefixed scripts; the agent ignores the configured
timeout for them, so the server refuses a positive `duration` rather than implying the block
will expire. A successful response means Wazuh delivered the command to the agent, not that
the script ran, so results report `execution_status: "dispatched"`.

`!firewall-drop` and `!host-deny` are sent only by `wazuh_block_ip`, `wazuh_firewall_drop`
and `wazuh_host_deny`, which refuse loopback, the Manager's address and `WAZUH_PROTECTED_IPS`;
the generic `wazuh_active_response` tool refuses both commands.

## Indexer indices used

From `src/wazuh_mcp_server/api/wazuh_indexer.py`. All access is `POST <index>/_search`.

| Index pattern | Used for |
|---|---|
| `wazuh-alerts-*` | Alert search, summaries, aggregations (`size=0`), threat and compliance evidence |
| `wazuh-states-vulnerabilities*` | Vulnerability listing, critical vulnerabilities, summaries |

On 5.x see [Wazuh 5.x](#wazuh-5x) for the indices that replace these and the removed endpoints.

With `ccs_prefix` set on a cluster in `clusters.json`, the pattern becomes
`<prefix>:wazuh-alerts-*` for OpenSearch Cross-Cluster Search (`*` targets all remotes). The
Indexer account needs search access to these patterns only.

## Configuration

```bash
# Manager API
WAZUH_HOST=wazuh-manager.example.com
WAZUH_PORT=55000
WAZUH_USER=mcp-service
WAZUH_PASS=<password>
WAZUH_VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=false   # default; true skips Manager certificate verification
WAZUH_CA_BUNDLE=/app/certs/ca.pem   # CA for the Manager and Indexer; replaces the system store

# Indexer (required for alert and vulnerability tools)
WAZUH_INDEXER_HOST=wazuh-indexer.example.com   # prefix with http:// for a plain-HTTP node
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=<user>
WAZUH_INDEXER_PASS=<password>
WAZUH_INDEXER_VERIFY_SSL=true
```

The stock Manager API certificate (`/var/ossec/api/configuration/ssl/server.crt`) is self-signed for
`CN=wazuh.com` with no subjectAltName, so it fails verification for any `WAZUH_HOST`. Reissue it
with a subjectAltName for the Manager's hostname or IP and point `WAZUH_CA_BUNDLE` at the signing
CA, or set `WAZUH_ALLOW_SELF_SIGNED=true` to connect without verification. See
[Manager TLS](docs/configuration.md#manager-tls).

See [docs/configuration.md](docs/configuration.md) for every setting and
[docs/MULTI_CLUSTER.md](docs/MULTI_CLUSTER.md) for per-cluster configuration.

## Verifying a deployment

```bash
# Manager API reachable, certificate valid for WAZUH_HOST, credentials accepted;
# GET / reports data.api_version. Drop --cacert to test against the system store.
TOKEN=$(curl -s --cacert "$WAZUH_CA_BUNDLE" -u "$WAZUH_USER:$WAZUH_PASS" -X POST \
  "https://$WAZUH_HOST:55000/security/user/authenticate?raw=true")
curl -s --cacert "$WAZUH_CA_BUNDLE" -H "Authorization: Bearer $TOKEN" "https://$WAZUH_HOST:55000/"

# Server liveness (does not contact Wazuh)
curl -s http://localhost:3000/health

# Readiness: Manager, Indexer and memory headroom; 503 when a check fails
curl -s http://localhost:3000/ready
```

The `validate_wazuh_connection` tool reports the Manager connection status from inside an MCP
session.

## References

- [Wazuh API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Wazuh release notes](https://documentation.wazuh.com/current/release-notes/index.html)
- [Wazuh upgrade guide](https://documentation.wazuh.com/current/upgrade-guide/index.html)
