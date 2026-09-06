from app.detection.hybrid_detector import (
    analyze_url_hybrid,
    calculate_heuristic_score,
    determine_risk_level,
)


def test_hybrid_result_structure():
    result = analyze_url_hybrid(
        "https://www.python.org/"
    )

    assert result["url"] == "https://www.python.org/"
    assert 0 <= result["final_score"] <= 100

    assert result["risk_level"] in {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert "heuristic" in result["components"]
    assert "machine_learning" in result["components"]


def test_suspicious_url_has_reasons():
    result = analyze_url_hybrid(
        "http://203.0.113.50:8080/"
        "paypal/account/verify"
    )

    assert len(result["reasons"]) > 0
    assert result["components"]["heuristic"]["score"] > 0


def test_ip_address_increases_heuristic_score():
    safe_score, _ = calculate_heuristic_score(
        "https://example.com/"
    )

    ip_score, _ = calculate_heuristic_score(
        "http://203.0.113.50/login"
    )

    assert ip_score > safe_score



def test_risk_level_boundaries():
    assert determine_risk_level(0) == "low"
    assert determine_risk_level(19.99) == "low"

    assert determine_risk_level(20) == "guarded"
    assert determine_risk_level(34.99) == "guarded"

    assert determine_risk_level(35) == "medium"
    assert determine_risk_level(54.99) == "medium"

    assert determine_risk_level(55) == "high"
    assert determine_risk_level(74.99) == "high"

    assert determine_risk_level(75) == "critical"
