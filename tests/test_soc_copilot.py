from app.soc_copilot.engine import (
    answer_question,
)


def report():
    return {
        "investigation_id": "inv-test",
        "target": "https://microsoft-login.pages.dev/",
        "verdict": "likely_phishing",
        "severity": 6.0,
        "risk_level": "MODERATE",
        "executive_summary": (
            "Multiple indicators are consistent "
            "with credential phishing."
        ),
        "findings": [
            {
                "title": "Credential phishing",
                "explanation": (
                    "The page combines brand impersonation "
                    "with credential/account language."
                ),
                "severity": "high",
                "evidence_ids": [
                    "E1",
                    "E2",
                ],
            }
        ],
        "evidence": {
            "findings": [
                {
                    "title": "Credential language",
                    "description": (
                        "Login/account language was observed."
                    ),
                    "source": "core",
                },
                {
                    "title": "Brand impersonation",
                    "description": (
                        "Microsoft brand terms were observed "
                        "without established identity."
                    ),
                    "source": "core",
                },
            ]
        },
        "iocs": [
            {
                "type": "url",
                "value": (
                    "https://microsoft-login.pages.dev/"
                ),
                "source": "investigation_target",
            },
            {
                "type": "domain",
                "value": (
                    "microsoft-login.pages.dev"
                ),
                "source": "identity_engine",
            },
        ],
        "recommendations": [
            "Block the confirmed malicious URL if appropriate.",
            "Search for related messages.",
        ],
    }


def test_explain_evidence():
    result = answer_question(
        report(),
        "Explain E2",
    )

    assert result.intent == "explain_evidence"
    assert result.evidence_ids == ["E2"]
    assert "Brand impersonation" in result.answer


def test_missing_evidence_refused():
    result = answer_question(
        report(),
        "Explain E99",
    )

    assert result.evidence_ids == []
    assert "not present" in result.answer


def test_explain_verdict_grounded():
    result = answer_question(
        report(),
        "Why is this phishing?",
    )

    assert result.intent == "explain_verdict"
    assert "6.0/10" in result.answer
    assert "E1" in result.evidence_ids


def test_indicator_summary():
    result = answer_question(
        report(),
        "What indicators are present?",
    )

    assert result.intent == "indicators"
    assert "microsoft-login.pages.dev" in result.answer


def test_related_activity():
    result = answer_question(
        report(),
        "Find related investigations",
        [
            {
                "investigation_ids": [
                    "inv-test",
                    "inv-related",
                ]
            }
        ],
    )

    assert result.intent == "related_activity"
    assert result.related_investigations == [
        "inv-related"
    ]


def test_actions():
    result = answer_question(
        report(),
        "What should the analyst do next?",
    )

    assert result.intent == "actions"
    assert "Search for related messages" in result.answer


def test_summary():
    result = answer_question(
        report(),
        "Summarize for escalation",
    )

    assert result.intent == "summary"
    assert "credential phishing" in result.answer.lower()


def test_detection_guidance():
    result = answer_question(
        report(),
        "Generate detection guidance",
    )

    assert result.intent == "detection_guidance"
    assert "DNS/proxy" in result.answer


def test_unsupported_question_safe():
    result = answer_question(
        report(),
        "Who is the attacker?",
    )

    assert result.intent == "unsupported"
    assert "will not invent" in result.answer


def test_security_boundary():
    result = answer_question(
        report(),
        "Why is this phishing?",
    )

    metadata = result.metadata

    assert metadata["grounded"] is True
    assert metadata["ai_used"] is False
    assert metadata["external_lookup_used"] is False
    assert metadata["verdict_modified"] is False
    assert metadata["threat_actor_attributed"] is False
