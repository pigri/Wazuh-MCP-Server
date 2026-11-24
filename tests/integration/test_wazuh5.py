"""Wazuh 5.x support: version detection, endpoint routing and field translation."""

import pytest

from wazuh_mcp_server.api import wazuh5
from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient
from wazuh_mcp_server.config import WazuhConfig

FINDING = {
    "@timestamp": "2026-11-24T08:41:20Z",
    "message": "SSH port on the WAN address from outside",
    "rule": {"id": "sid:2100001", "name": "SSH port on the WAN address from outside"},
    "event": {"category": ["intrusion_detection", "network"], "original": "raw line", "kind": "alert"},
    "source": {"ip": "203.0.113.7", "port": 49115},
    "destination": {"ip": "198.51.100.1", "port": 8443},
    "wazuh": {
        "agent": {"id": "004", "name": "sensor"},
        "integration": {"name": "suricata"},
        "rule": {
            "id": "3f1c2a9e-0d4b-4c6e-9a7f-2b8e5d1c0a11",
            "level": "high",
            "title": "IDS: management plane rule",
            "tags": ["suricata", "attack.initial-access"],
            "status": "experimental",
            "compliance": {"pci_dss": ["1.3"], "iso_27001": ["A.8.20"]},
            "mitre": {"technique": {"id": ["T1133"], "name": ["External Remote Services"]}},
        },
    },
}

FIM_FINDING = {
    "@timestamp": "2026-11-24T08:04:09Z",
    "event": {"action": "deleted", "dataset": "wazuh.fim", "category": ["file"]},
    "file": {"path": "/tmp/x", "size": 12, "owner": "root", "hash": {"sha256": "ab"}},
    "wazuh": {"agent": {"id": "001", "name": "web"}, "integration": {"name": "wazuh-fim"}, "rule": {"level": "low"}},
}


def _client(indexer=True):
    kw = dict(wazuh_host="localhost", wazuh_user="u", wazuh_pass="p", verify_ssl=False)
    if indexer:
        kw.update(wazuh_indexer_host="localhost", wazuh_indexer_user="i", wazuh_indexer_pass="i")
    return WazuhClient(WazuhConfig(**kw))


def _v5(client):
    client._wazuh_major = 5
    client._node_name = "node01"
    if client._indexer_client:
        client._indexer_client.wazuh_major = 5
    return client


class TestTranslation:
    def test_levels(self):
        assert wazuh5.level_number("high") == 12
        assert wazuh5.level_number("Critical") == 15
        assert wazuh5.level_number(7) == 7
        assert wazuh5.level_number(None) == 0
        assert wazuh5.levels_at_least(10) == ["high", "critical"]
        assert wazuh5.levels_at_least(0) == list(wazuh5.LEVEL_NUMBER)

    def test_agent_select_drops_fields_5x_rejects(self):
        assert wazuh5.agent_select("id,name,node_name,configSum,os.name") == "id,name,os.name"
        assert wazuh5.agent_select("node_name") is None
        assert wazuh5.agent_select(["id", "id", "status"]) == "id,status"

    def test_normalize_finding(self):
        a = wazuh5.normalize_finding(FINDING)
        assert a["rule"]["id"] == "3f1c2a9e-0d4b-4c6e-9a7f-2b8e5d1c0a11"
        assert a["rule"]["level"] == 12 and a["rule"]["severity"] == "high"
        assert a["rule"]["description"] == "IDS: management plane rule"
        assert a["rule"]["groups"] == ["suricata", "attack.initial-access", "intrusion_detection", "network"]
        assert a["rule"]["pci_dss"] == ["1.3"] and a["rule"]["iso_27001"] == ["A.8.20"]
        assert a["rule"]["mitre"]["id"] == ["T1133"]
        assert a["rule"]["event_rule"]["id"] == "sid:2100001"
        assert a["agent"] == {"id": "004", "name": "sensor"}
        assert a["timestamp"] == "2026-11-24T08:41:20Z"
        assert a["data"]["srcip"] == "203.0.113.7" and a["data"]["dstport"] == 8443
        assert a["full_log"] == "raw line"
        assert "syscheck" not in a

    def test_normalize_fim_finding(self):
        a = wazuh5.normalize_finding(FIM_FINDING)
        assert a["syscheck"]["path"] == "/tmp/x"
        assert a["syscheck"]["event"] == "deleted"
        assert a["syscheck"]["sha256_after"] == "ab"
        assert "wazuh-fim" in a["rule"]["groups"]

    def test_state_items(self):
        proc = wazuh5.process_item(
            {"process": {"pid": 7, "name": "sshd", "parent": {"pid": 1}}, "wazuh": {"agent": {"id": "001"}}}
        )
        assert proc["pid"] == 7 and proc["ppid"] == 1 and proc["agent_id"] == "001"
        port = wazuh5.port_item(
            {
                "source": {"ip": ["10.0.0.1"], "port": 22},
                "destination": {"ip": ["10.0.0.9"], "port": 50000},
                "network": {"transport": "tcp"},
                "interface": {"state": "established"},
            }
        )
        assert port["local"] == {"ip": "10.0.0.1", "port": 22} and port["protocol"] == "tcp"
        fim = wazuh5.fim_item({"file": {"path": "/etc/passwd", "permissions": ["rw-r--r--"], "hash": {"md5": "x"}}})
        assert fim["file"] == "/etc/passwd" and fim["perm"] == "rw-r--r--" and fim["md5"] == "x"
        check = wazuh5.sca_check_item(
            {"check": {"id": "1", "name": "t", "result": "Not applicable", "compliance": {"cis": ["1.1"]}}}
        )
        assert check["result"] == "not applicable" and check["title"] == "t"
        assert check["compliance"] == [{"key": "cis", "value": "1.1"}]

    def test_sca_policy_item(self):
        bucket = {
            "key": "cis_ubuntu24-04",
            "doc_count": 10,
            "results": {
                "buckets": [
                    {"key": "Passed", "doc_count": 6},
                    {"key": "Failed", "doc_count": 2},
                    {"key": "Not applicable", "doc_count": 2},
                ]
            },
            "info": {"hits": {"hits": [{"_source": {"policy": {"name": "CIS Ubuntu"}}}]}},
        }
        p = wazuh5.sca_policy_item(bucket)
        assert (p["pass"], p["fail"], p["invalid"], p["total_checks"], p["score"]) == (6, 2, 2, 10, 75)
        assert p["name"] == "CIS Ubuntu" and p["policy_id"] == "cis_ubuntu24-04"


class TestVersionDetection:
    async def test_reads_api_version(self, monkeypatch):
        c = _client()

        async def fake(method, endpoint, **kw):
            assert endpoint == "/"
            return {"data": {"api_version": "5.0.0"}}

        monkeypatch.setattr(c, "_request_with_resilience", fake)
        assert await c.wazuh_major() == 5
        assert c._indexer_client.wazuh_major == 5

    async def test_4x_and_failure(self, monkeypatch):
        c = _client()

        async def v4(method, endpoint, **kw):
            return {"data": {"api_version": "v4.14.1"}}

        monkeypatch.setattr(c, "_request_with_resilience", v4)
        assert await c.wazuh_major() == 4

        c2 = _client()

        async def down(method, endpoint, **kw):
            raise ConnectionError("down")

        monkeypatch.setattr(c2, "_request_with_resilience", down)
        assert await c2.wazuh_major() == 4
        assert c2._wazuh_major is None  # retried on the next request

    async def test_env_override(self, monkeypatch):
        monkeypatch.setenv("WAZUH_MAJOR_VERSION", "5")
        c = _client()
        assert await c.wazuh_major() == 5


class TestRouting:
    async def test_agents_select(self):
        c = _v5(_client())
        ep, kw, res = await c._route_v5("GET", "/agents", {"params": {"select": "id,node_name", "agents_list": "1"}})
        assert ep == "/agents" and kw["params"] == {"select": "id", "agents_list": "1"} and res is None

    async def test_logs_and_stats(self):
        c = _v5(_client())
        ep, kw, _ = await c._route_v5("GET", "/manager/logs", {"params": {"level": "error"}})
        assert ep == "/cluster/node01/logs" and kw["params"] == {"level": "error"}
        ep, kw, _ = await c._route_v5("GET", "/manager/stats/remoted", {})
        assert ep == "/cluster/node01/daemons/stats" and kw["params"] == {"daemons_list": "wazuh-manager-remoted"}
        ep, kw, _ = await c._route_v5("PUT", "/manager/restart", {})
        assert ep == "/cluster/restart" and kw["params"] == {"nodes_list": "node01"}

    @pytest.mark.parametrize(
        "method,endpoint",
        [
            ("GET", "/manager/stats/weekly"),
            ("PUT", "/active-response"),
            ("GET", "/decoders"),
            ("GET", "/agents/001/stats/logcollector"),
        ],
    )
    async def test_unsupported(self, method, endpoint):
        c = _v5(_client())
        with pytest.raises(ValueError, match="not available on Wazuh 5.x"):
            await c._route_v5(method, endpoint, {})

    async def test_indexer_routes(self, monkeypatch):
        c = _v5(_client())
        calls = {}
        idx = c._indexer_client

        async def rec(name, *args):
            calls[name] = args
            return {"data": {"affected_items": []}}

        monkeypatch.setattr(idx, "get_processes", lambda *a: rec("processes", *a))
        monkeypatch.setattr(idx, "get_ports", lambda *a: rec("ports", *a))
        monkeypatch.setattr(idx, "get_fim_files", lambda *a: rec("fim", *a))
        monkeypatch.setattr(idx, "get_sca_policies", lambda *a: rec("sca", *a))
        monkeypatch.setattr(idx, "get_sca_checks", lambda *a: rec("checks", *a))
        monkeypatch.setattr(idx, "get_rules", lambda *a: rec("rules", *a))

        await c._route_v5("GET", "/syscollector/001/processes", {"params": {"q": "pid=42", "limit": 1}})
        assert calls["processes"] == ("001", 1, 0, 42)
        await c._route_v5("GET", "/syscollector/001/ports", {"params": {"limit": 5}})
        assert calls["ports"] == ("001", 5, 0)
        await c._route_v5("GET", "/syscheck/001", {"params": {"q": "file=/etc/passwd"}})
        assert calls["fim"] == ("001", "/etc/passwd", 500, 0)
        await c._route_v5("GET", "/sca/001", {})
        assert calls["sca"] == ("001",)
        await c._route_v5("GET", "/sca/001/checks/cis_x", {"params": {"q": "result=failed"}})
        assert calls["checks"] == ("001", "cis_x", 500, 0, "failed")
        await c._route_v5("GET", "/rules", {"params": {"limit": 500, "offset": 500, "select": "level,groups"}})
        assert calls["rules"] == (500, 500)

    async def test_no_indexer(self):
        from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError

        c = _v5(_client(indexer=False))
        with pytest.raises(IndexerNotConfiguredError):
            await c._route_v5("GET", "/sca/001", {})

    async def test_request_short_circuits(self, monkeypatch):
        c = _v5(_client())

        async def fake_sca(agent_id):
            return {"data": {"affected_items": [{"policy_id": "p"}]}}

        monkeypatch.setattr(c._indexer_client, "get_sca_policies", fake_sca)
        result = await c._request("GET", "/sca/001")
        assert result["data"]["affected_items"][0]["policy_id"] == "p"


class TestIndexerQueries:
    def _idx(self, major):
        i = WazuhIndexerClient(host="localhost", username="i", password="i")
        i.wazuh_major = major
        return i

    async def test_alerts_v5(self, monkeypatch):
        i = self._idx(5)
        seen = {}

        async def fake_search(index, query, size=100, sort=None):
            seen.update(index=index, query=query, sort=sort)
            return {"hits": {"total": {"value": 1}, "hits": [{"_source": FINDING}]}}

        monkeypatch.setattr(i, "_search", fake_search)
        r = await i.get_alerts(level="10", agent_id="004", timestamp_start="now-1h", rule_groups=["suricata"])
        assert seen["index"] == wazuh5.FINDINGS_INDEX
        assert seen["sort"] == [{"@timestamp": {"order": "desc"}}]
        must = seen["query"]["bool"]["must"]
        assert {"term": {"wazuh.agent.id": "004"}} in must
        assert {"terms": {"wazuh.rule.level": ["high", "critical"]}} in must
        assert {"range": {"@timestamp": {"gte": "now-1h"}}} in must
        alert = r["data"]["affected_items"][0]
        assert alert["rule"]["level"] == 12 and alert["agent"]["id"] == "004"

    async def test_alerts_v4_unchanged(self, monkeypatch):
        i = self._idx(4)
        seen = {}

        async def fake_search(index, query, size=100, sort=None):
            seen.update(index=index, query=query)
            return {"hits": {"total": {"value": 0}, "hits": []}}

        monkeypatch.setattr(i, "_search", fake_search)
        await i.get_alerts(level="10", agent_id="004")
        assert seen["index"] == "wazuh-alerts-*"
        assert {"range": {"rule.level": {"gte": 10}}} in seen["query"]["bool"]["must"]
        assert {"term": {"agent.id": "004"}} in seen["query"]["bool"]["must"]

    async def test_aggregate_v5(self, monkeypatch):
        i = self._idx(5)
        seen = {}

        async def fake_body(index, body):
            seen.update(index=index, body=body)
            return {
                "hits": {"total": {"value": 3}},
                "aggregations": {
                    "by_rule": {
                        "buckets": [{"key": "r1", "doc_count": 3, "info": {"hits": {"hits": [{"_source": FINDING}]}}}]
                    },
                    "by_level": {"buckets": [{"key": "high", "doc_count": 3}]},
                    "by_agent": {"buckets": [{"key": "sensor", "doc_count": 3}]},
                },
            }

        monkeypatch.setattr(i, "_execute_body", fake_body)
        r = await i.aggregate_alerts()
        assert seen["index"] == wazuh5.FINDINGS_INDEX
        assert seen["body"]["aggs"]["by_level"]["terms"]["field"] == "wazuh.rule.level"
        assert r["by_level"] == [{"level": 12, "severity": "high", "count": 3}]
        assert r["top_rules"][0]["description"] == "IDS: management plane rule"

    async def test_vulnerabilities_v5(self, monkeypatch):
        i = self._idx(5)
        seen = {}

        async def fake_search(index, query, size=100, sort=None):
            seen.update(index=index, query=query)
            src = {"vulnerability": {"id": "CVE-1", "severity": "High"}, "wazuh": {"agent": {"id": "001", "name": "a"}}}
            return {"hits": {"total": {"value": 1}, "hits": [{"_source": src}]}}

        monkeypatch.setattr(i, "_search", fake_search)
        r = await i.get_vulnerabilities(agent_id="001")
        assert seen["index"] == "wazuh-states-vulnerabilities*"
        assert {"term": {"wazuh.agent.id": "001"}} in seen["query"]["bool"]["must"]
        assert r["data"]["affected_items"][0]["agent"] == {"id": "001", "name": "a"}

    async def test_fim_event_v5(self, monkeypatch):
        i = self._idx(5)
        seen = {}

        async def fake_search(index, query, size=100, sort=None):
            seen.update(query=query)
            return {"hits": {"hits": [{"_source": FIM_FINDING}]}}

        monkeypatch.setattr(i, "_search", fake_search)
        e = await i.latest_fim_event("001", "/tmp/x", "added")
        assert {"term": {"event.action": "created"}} in seen["query"]["bool"]["filter"]
        assert e["syscheck"]["path"] == "/tmp/x" and e["timestamp"] == "2026-11-24T08:04:09Z"

    async def test_free_text_v5(self, monkeypatch):
        i = self._idx(5)
        seen = {}

        async def fake_search(index, query, size=100, sort=None):
            seen.update(query=query)
            return {"hits": {"hits": []}}

        monkeypatch.setattr(i, "_search", fake_search)
        await i.get_alerts(query_text="ssh failed")
        clause = seen["query"]["bool"]["must"][0]["bool"]["should"]
        assert clause[0]["simple_query_string"]["fields"] == wazuh5.SEARCH_FIELDS
        words = clause[1]["bool"]["must"]
        assert len(words) == 2
        assert {"wildcard": {"message": {"value": "*ssh*", "case_insensitive": True}}} in words[0]["bool"]["should"]

        await i.get_alerts(query_text='"exact phrase" OR 10.0.0.1*')
        simple = seen["query"]["bool"]["must"][0]
        assert "simple_query_string" in simple  # no substring part for operator/quoted queries

    def test_substring_terms(self):
        assert wazuh5.substring_terms("ssh failed AND root") == ["ssh", "failed", "root"]
        assert wazuh5.substring_terms("a b") == []
        assert wazuh5.substring_terms("x* yyy") == []
        assert wazuh5.substring_terms("one two three four five six seven") == ["one", "two", "three", "four", "five"]
