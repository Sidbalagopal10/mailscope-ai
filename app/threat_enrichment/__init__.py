"""
Unified threat-intelligence enrichment layer.

This package normalizes existing deterministic intelligence
into evidence suitable for SOC investigations.

Threat intelligence is evidence, not a verdict.
"""

from app.threat_enrichment.orchestrator import enrich_target

__all__ = ["enrich_target"]
