from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd

from app.detection.brand_intelligence import (
    is_known_official_domain,
)

from app.ml.url_features import (
    extract_url_features,
)


MODEL_PATH = Path(
    "models/url_classifier.joblib"
)


class URLClassifierError(
    Exception
):
    pass


class URLClassifier:
    def __init__(
        self,
        model_path: Path = MODEL_PATH,
    ) -> None:
        self.model_path = model_path
        self.model = None
        self.calibrator = None
        self.feature_names: list[
            str
        ] = []
        self.model_type = "unknown"
        self.model_version = "unknown"
        self.decision_threshold = 0.5

        self.load()

    def load(self) -> None:
        if not self.model_path.exists():
            raise URLClassifierError(
                "URL classifier model was not "
                f"found at {self.model_path}."
            )

        package = joblib.load(
            self.model_path
        )

        if not isinstance(
            package,
            dict,
        ):
            raise URLClassifierError(
                "The classifier package has "
                "an invalid format."
            )

        required_keys = {
            "model",
            "feature_names",
        }

        missing_keys = (
            required_keys
            - set(package)
        )

        if missing_keys:
            raise URLClassifierError(
                "The classifier package is "
                "missing: "
                f"{sorted(missing_keys)}"
            )

        self.model = package["model"]
        self.calibrator = package.get(
            "probability_calibrator"
        )

        self.feature_names = list(
            package["feature_names"]
        )

        self.model_type = package.get(
            "model_type",
            type(self.model).__name__,
        )

        self.model_version = package.get(
            "model_version",
            "unknown",
        )

        self.decision_threshold = float(
            package.get(
                "decision_threshold",
                0.5,
            )
        )

    def build_feature_frame(
        self,
        url: str,
    ) -> pd.DataFrame:
        extracted = (
            extract_url_features(
                url
            )
        )

        missing = [
            name
            for name in (
                self.feature_names
            )
            if name not in extracted
        ]

        if missing:
            raise URLClassifierError(
                "Feature extractor is missing "
                f"model features: {missing}"
            )

        ordered = {
            name: extracted[name]
            for name in (
                self.feature_names
            )
        }

        return pd.DataFrame(
            [ordered]
        )

    def calibrated_probability(
        self,
        raw_probability: float,
    ) -> float:
        if self.calibrator is None:
            return raw_probability

        calibrated = (
            self.calibrator.predict(
                np.array(
                    [raw_probability]
                )
            )
        )

        return float(
            calibrated[0]
        )

    def predict(
        self,
        url: str,
    ) -> dict[str, Any]:
        feature_frame = (
            self.build_feature_frame(
                url
            )
        )

        raw_probability = float(
            self.model.predict_proba(
                feature_frame
            )[0][1]
        )

        probability = (
            self.calibrated_probability(
                raw_probability
            )
        )

        predicted_label = int(
            probability
            >= self.decision_threshold
        )

        return {
            "label": predicted_label,
            "classification": (
                "phishing"
                if predicted_label
                else "benign"
            ),
            "raw_phishing_probability": round(
                raw_probability,
                6,
            ),
            "phishing_probability": round(
                probability,
                6,
            ),
            "phishing_percentage": round(
                probability * 100,
                2,
            ),
            "is_phishing": bool(
                predicted_label
            ),
            "model_type": (
                self.model_type
            ),
            "model_version": (
                self.model_version
            ),
            "decision_threshold": round(
                self.decision_threshold,
                6,
            ),
        }


_classifier_instance = None


def get_url_classifier() -> (
    URLClassifier
):
    global _classifier_instance

    if _classifier_instance is None:
        _classifier_instance = (
            URLClassifier()
        )

    return _classifier_instance


def predict_url(
    url: str,
) -> dict:
    """
    Return the ML result plus a transparent evidence guardrail.

    The raw model probability remains visible. A conditional
    official-domain adjustment is applied only when the URL has
    no strong contradictory evidence.
    """
    result = get_url_classifier().predict(
        url
    )

    original_probability = float(
        result.get(
            "phishing_probability",
            0.0,
        )
        or 0.0
    )

    parsed_url = urlparse(
        str(url or "").strip()
    )

    hostname = (
        parsed_url.hostname
        or ""
    ).lower()

    features = extract_url_features(
        url
    )

    official_domain = (
        is_known_official_domain(
            hostname
        )
    )

    contradictory_evidence = any(
        [
            not bool(
                features.get(
                    "uses_https",
                    0,
                )
            ),
            bool(
                features.get(
                    "hostname_is_ip",
                    0,
                )
            ),
            bool(
                features.get(
                    "brand_impersonation",
                    0,
                )
            ),
            bool(
                features.get(
                    "contains_suspicious_port",
                    0,
                )
            ),
            bool(
                features.get(
                    "contains_punycode",
                    0,
                )
            ),
            bool(
                features.get(
                    "count_at_symbols",
                    0,
                )
            ),
            int(
                features.get(
                    "count_high_signal_keywords",
                    0,
                )
                or 0
            )
            >= 2,
        ]
    )

    guardrail_applied = bool(
        official_domain
        and not contradictory_evidence
    )

    result[
        "probability_before_guardrail"
    ] = round(
        original_probability,
        6,
    )

    result[
        "official_domain_detected"
    ] = bool(
        official_domain
    )

    result[
        "official_domain_guardrail"
    ] = bool(
        guardrail_applied
    )

    result[
        "guardrail_contradictory_evidence"
    ] = bool(
        contradictory_evidence
    )

    if guardrail_applied:
        # The ML model remains visible, but it cannot independently
        # declare a clean official HTTPS URL phishing.
        adjusted_probability = min(
            original_probability,
            0.12,
        )

        result[
            "phishing_probability"
        ] = round(
            adjusted_probability,
            6,
        )

        result[
            "phishing_percentage"
        ] = round(
            adjusted_probability * 100,
            2,
        )

        result["label"] = 0
        result["classification"] = "benign"
        result["is_phishing"] = False

        result[
            "decision_explanation"
        ] = (
            "The raw ML result was reduced because the URL "
            "uses a conditionally recognized official domain, "
            "HTTPS, a normal port, and no strong impersonation "
            "or credential-lure indicators."
        )

    else:
        result[
            "decision_explanation"
        ] = (
            "No official-domain adjustment was applied. "
            "Unknown domains remain neutral and are evaluated "
            "using the available URL evidence."
        )

    return result


def reload_url_classifier():
    global _classifier_instance

    _classifier_instance = (
        URLClassifier()
    )

    return _classifier_instance
