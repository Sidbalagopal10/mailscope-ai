from app.threat_graph.engine import (
    build_threat_graph,
)


def sample_report():
    return {
        "investigation_id": "inv-test",
        "target": "https://evil.example/login",
        "target_type": "url",
        "identity": {
            "organization": "Example Organization",
            "canonical_domain": "example.org",
        },
        "iocs": [
            {
                "type": "ip",
                "value": "1.2.3.4",
                "source": "dns",
            },
            {
                "type": "email",
                "value": "sender@evil.example",
                "source": "email",
            },
        ],
    }


def test_graph_has_investigation():
    graph = build_threat_graph(
        sample_report()
    )

    types = {
        node["node_type"]
        for node in graph["nodes"]
    }

    assert "investigation" in types


def test_graph_extracts_url_domain():
    graph = build_threat_graph(
        sample_report()
    )

    values = {
        node["value"]
        for node in graph["nodes"]
    }

    assert (
        "https://evil.example/login"
        in values
    )

    assert "evil.example" in values


def test_graph_contains_iocs():
    graph = build_threat_graph(
        sample_report()
    )

    values = {
        node["value"]
        for node in graph["nodes"]
    }

    assert "1.2.3.4" in values
    assert "sender@evil.example" in values


def test_graph_contains_identity():
    graph = build_threat_graph(
        sample_report()
    )

    values = {
        node["value"]
        for node in graph["nodes"]
    }

    assert "Example Organization" in values
    assert "example.org" in values


def test_graph_security_boundary():
    graph = build_threat_graph(
        sample_report()
    )

    metadata = graph["metadata"]

    assert metadata["deterministic"] is True
    assert metadata["ai_used"] is False
    assert metadata["external_lookup_used"] is False
    assert metadata["threat_actor_attributed"] is False
    assert metadata["evidence_backed"] is True
