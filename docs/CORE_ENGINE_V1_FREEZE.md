# Core Engine v1.0 — Feature Freeze

Core Engine v1.0 is frozen.

## Allowed after freeze

- Security fixes
- Correctness fixes
- Performance fixes
- Benchmark corrections
- False-positive fixes supported by reproducible evidence
- Critical false-negative fixes supported by reproducible evidence

## Not part of Core v1

Do not keep adding ad-hoc:

- URL keywords
- brand lists
- allowlists
- blocklists
- scoring bonuses
- scoring penalties
- one-off organization exceptions

New intelligence belongs in the investigation/orchestration layer.

## Identity principles

Identity confidence is not phishing probability.

UNKNOWN does not mean malicious.

CONFLICTING does not mean malicious.

VERIFIED does not guarantee that a page is safe.

A legitimate domain can be compromised.

An unknown organization can be legitimate.

## Release benchmark

Before Core v1:

- TP: 3
- FP: 0
- FN: 297
- Recall: 1.00%
- F1: 0.0198

Core v1:

- TP: 35
- FP: 0
- FN: 265
- Recall: 11.67%
- F1: 0.2090

Dataset:

- 500 Tranco benign URLs
- 300 OpenPhish URLs
- OpenPhish used only as benchmark ground truth

Core v1 is not claimed to be production-grade phishing coverage.

The next system layer is the AI Security Analyst.
