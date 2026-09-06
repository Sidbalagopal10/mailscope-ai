import hashlib
from urllib.parse import urlsplit

from app.threat_graph.models import (
    GraphEdge,
    GraphNode,
)


def _node_id(
    node_type,
    value,
):
    digest = hashlib.sha256(
        f"{node_type}:{value}".encode()
    ).hexdigest()[:16]

    return f"{node_type}-{digest}"


def build_threat_graph(
    report: dict,
):
    nodes = {}
    edges = {}

    def add_node(
        node_type,
        value,
        label=None,
    ):
        if not value:
            return None

        value = str(value)

        node_id = _node_id(
            node_type,
            value,
        )

        nodes[node_id] = GraphNode(
            node_id=node_id,
            node_type=node_type,
            value=value,
            label=label or value,
        )

        return node_id

    def add_edge(
        source,
        target,
        relationship,
        evidence_source,
    ):
        if not source or not target:
            return

        key = (
            source,
            target,
            relationship,
        )

        edges[key] = GraphEdge(
            source=source,
            target=target,
            relationship=relationship,
            evidence_source=evidence_source,
        )

    investigation_id = str(
        report.get(
            "investigation_id",
            "unknown",
        )
    )

    investigation_node = add_node(
        "investigation",
        investigation_id,
    )

    target = report.get("target")

    target_type = str(
        report.get(
            "target_type",
            "url",
        )
    ).lower()

    target_node = None

    if target:
        target_node = add_node(
            target_type,
            target,
        )

        add_edge(
            investigation_node,
            target_node,
            "investigated_target",
            "canonical_report",
        )

    if target and target_type == "url":
        try:
            hostname = urlsplit(
                target
            ).hostname

            if hostname:
                domain_node = add_node(
                    "domain",
                    hostname.lower(),
                )

                add_edge(
                    target_node,
                    domain_node,
                    "resolves_to_domain",
                    "report_target",
                )
        except ValueError:
            pass

    identity = (
        report.get("identity", {})
        or {}
    )

    organization = identity.get(
        "organization"
    )

    canonical_domain = identity.get(
        "canonical_domain"
    )

    organization_node = None

    if organization:
        organization_node = add_node(
            "organization",
            organization,
        )

        add_edge(
            investigation_node,
            organization_node,
            "identity_context",
            "identity_intelligence",
        )

    if canonical_domain:
        domain_node = add_node(
            "domain",
            canonical_domain,
        )

        if organization_node:
            add_edge(
                organization_node,
                domain_node,
                "canonical_domain",
                "identity_intelligence",
            )

    for ioc in (
        report.get("iocs", [])
        or []
    ):
        if not isinstance(ioc, dict):
            continue

        ioc_type = str(
            ioc.get(
                "type",
                "observable",
            )
        ).lower()

        ioc_value = ioc.get(
            "value"
        )

        if not ioc_value:
            continue

        if ioc_type == "hostname":
            ioc_type = "domain"

        if ioc_type == "sender":
            ioc_type = "email"

        ioc_node = add_node(
            ioc_type,
            ioc_value,
        )

        add_edge(
            investigation_node,
            ioc_node,
            "observed_indicator",
            str(
                ioc.get(
                    "source",
                    "report_ioc",
                )
            ),
        )

    return {
        "investigation_id": investigation_id,
        "nodes": [
            node.to_dict()
            for node in nodes.values()
        ],
        "edges": [
            edge.to_dict()
            for edge in edges.values()
        ],
        "metadata": {
            "engine_version": "threat-graph-v1.0",
            "deterministic": True,
            "ai_used": False,
            "external_lookup_used": False,
            "threat_actor_attributed": False,
            "evidence_backed": True,
        },
    }
