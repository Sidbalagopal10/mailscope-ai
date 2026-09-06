from __future__ import annotations

import json
from typing import Any

from app.analyst.evidence import (
    InvestigationEvidence,
)


SYSTEM_INSTRUCTIONS = """
You are an AI Security Analyst assisting a human SOC analyst.

You are NOT the detection engine.

You are given a structured evidence package produced by deterministic
security systems.

STRICT RULES:

1. Use ONLY the supplied evidence.
2. Never claim that an external security service detected something
   unless that evidence is explicitly supplied.
3. Never invent:
   - VirusTotal results
   - malware families
   - IP addresses
   - DNS records
   - WHOIS/RDAP facts
   - domain ages
   - certificate facts
   - email authentication results
   - threat actor attribution
   - campaign attribution
4. UNKNOWN identity is neutral.
5. CONFLICTING identity is not evidence of phishing.
6. VERIFIED identity is not proof that content is safe.
7. Cite evidence using only the supplied evidence IDs.
8. If evidence is insufficient, use verdict "insufficient_evidence".
9. Distinguish observations from interpretation.
10. Do not state certainty greater than the evidence supports.

Allowed verdicts:
- benign
- suspicious
- likely_phishing
- malicious
- insufficient_evidence

Return ONLY valid JSON.
""".strip()


def serialize_evidence(
    evidence: InvestigationEvidence,
) -> dict[str, Any]:
    findings = []

    for index, finding in enumerate(
        evidence.findings,
        start=1,
    ):
        findings.append(
            {
                "evidence_id": (
                    f"E{index}"
                ),

                "category": (
                    finding.category
                ),

                "title": (
                    finding.title
                ),

                "description": (
                    finding.description
                ),

                "severity": (
                    finding.severity
                ),

                "source": (
                    finding.source
                ),

                "confidence": (
                    finding.confidence
                ),
            }
        )

    return {
        "investigation_id": (
            evidence.investigation_id
        ),

        "target": (
            evidence.target
        ),

        "target_type": (
            evidence.target_type
        ),

        "core": (
            evidence.core
        ),

        "identity_summary": {
            "identity_known": (
                evidence.identity.get(
                    "identity_known"
                )
            ),

            "canonical_domain": (
                evidence.identity.get(
                    "canonical_domain"
                )
            ),

            "best_match": (
                evidence.identity.get(
                    "best_match"
                )
            ),
        },

        "findings": findings,

        "metadata": (
            evidence.metadata
        ),
    }


def build_analyst_prompt(
    evidence: InvestigationEvidence,
) -> str:
    package = serialize_evidence(
        evidence
    )

    schema = {
        "investigation_id": "string",

        "verdict": (
            "benign | suspicious | likely_phishing | "
            "malicious | insufficient_evidence"
        ),

        "confidence": (
            "number from 0 to 100"
        ),

        "executive_summary": "string",

        "findings": [
            {
                "title": "string",
                "explanation": "string",
                "evidence_ids": [
                    "E1"
                ],
                "severity": (
                    "info | low | medium | high | critical"
                ),
            }
        ],

        "recommended_actions": [
            "string"
        ],

        "mitre_attack": [
            {
                "technique_id": "string",
                "technique_name": "string",
                "reason": "string",
            }
        ],

        "limitations": [
            "string"
        ],
    }

    return (
        "Analyze the following evidence package.\n\n"
        "EVIDENCE PACKAGE:\n"
        + json.dumps(
            package,
            indent=2,
            default=str,
        )
        + "\n\n"
        + "REQUIRED OUTPUT JSON SCHEMA:\n"
        + json.dumps(
            schema,
            indent=2,
        )
        + "\n\n"
        + "Every factual finding must cite at least one "
        + "evidence_id from the supplied package."
    )
