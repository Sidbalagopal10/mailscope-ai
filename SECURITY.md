# Security Policy

## MailScope AI Security Policy

MailScope AI is a defensive cybersecurity and SOC investigation project.

Security issues affecting the application, credential handling, investigation integrity, or hosted demonstration should be reported responsibly.

## Supported Version

The current public release branch is the supported version for security fixes.

Older development snapshots, backup files, experimental branches, and locally modified copies may not receive security updates.

## Reporting a Vulnerability

Do not publish a suspected vulnerability in a public GitHub issue before it has been reviewed.

When the repository is public, use **GitHub Private Vulnerability Reporting** if it is enabled for the repository.

A useful vulnerability report should include:

- Affected component
- Description of the issue
- Steps required to reproduce it
- Expected behavior
- Observed behavior
- Security impact
- Relevant logs or screenshots with secrets removed
- Suggested mitigation, if known

Never include access tokens, OAuth refresh tokens, passwords, API keys, private email contents, or other secrets in vulnerability reports.

## Credentials and Secrets

MailScope AI must not store real credentials in source control.

Credential and OAuth files must remain outside Git.

Examples include:

```text
.env
credentials.json
credentials.json.*
token.json
token.json.*
token.*.json
*.oauth.json
```

API keys should be supplied using environment variables or the secret-management capabilities of the deployment environment.

Do not hard-code secrets into:

- Python source files
- Configuration files
- Tests
- Screenshots
- Documentation
- Commit messages
- Example datasets

## Google OAuth

Users enabling Gmail functionality must provide their own authorized Google OAuth configuration.

OAuth client credentials and user tokens are deployment-specific secrets and must not be distributed with the public repository.

If an OAuth token, refresh token, client secret, API key, or similar credential is accidentally disclosed, removing the file from Git does not make that credential safe.

The affected credential should be revoked or rotated through the relevant provider.

## Gmail Safety Model

MailScope AI includes Gmail observation and labeling capabilities.

Actions that modify Gmail state should require an explicit authorized workflow.

The application should not silently perform destructive mailbox changes based only on AI-generated interpretation.

OAuth scopes should follow least-privilege principles.

Public Gmail integration may require additional Google verification, consent, privacy, or security requirements depending on the scopes and deployment model.

## AI Security Boundary

MailScope AI intentionally separates deterministic security evidence from AI-assisted interpretation.

The AI or Copilot layer must not become the authoritative security decision engine.

Security controls include:

- Evidence-grounded findings
- Explicit evidence identifiers
- Unsupported-fact rejection
- Unsupported attribution refusal
- Separation of verdict and narrative
- Deterministic risk authority
- No automatic threat-actor attribution

AI-generated interpretation should be treated as analyst assistance rather than independent proof.

## Threat Intelligence Safety

External threat-intelligence results are supporting evidence.

A single enrichment result should not automatically determine a phishing verdict.

Examples include:

- VirusTotal results
- ThreatFox matches
- RDAP registration information
- DNS observations
- Certificate Transparency records
- IP and ASN information
- Shared-hosting infrastructure

Provider failure or absence of data should not automatically increase phishing risk.

Shared infrastructure alone should not be treated as proof that multiple investigations belong to the same attacker or campaign.

## Safe Testing

Do not intentionally browse suspicious or known-malicious URLs to test MailScope AI.

URLs can normally be supplied to the investigation engine as strings.

Prefer:

- Controlled fixtures
- Synthetic indicators
- Sanitized test datasets
- Isolated test environments

Do not upload confidential organizational email, credentials, private attachments, regulated information, or other sensitive material to a public demonstration instance.

## Local Data and Privacy

MailScope AI currently uses SQLite in its portfolio architecture.

The local database may contain information such as:

- Scan history
- Investigation metadata
- Email-related metadata
- Case information
- Campaign relationships
- Analyst workflow data

Local database files should not be committed to a public repository unless they are deliberately created and sanitized test fixtures.

The following runtime data should generally remain outside source control:

```text
.env
phishing_detector.db
logs/
reports/
data/investigations/
```

Users are responsible for protecting locally stored investigation data and any credentials configured for external services.

## Hosted Demonstration

The hosted version of MailScope AI is intended for demonstration and portfolio evaluation.

It is not currently presented as an enterprise production service.

Depending on the hosting provider, local storage may be ephemeral and application instances may restart or sleep.

Users should not rely on the hosted demonstration for:

- Durable case retention
- Compliance storage
- Incident evidence preservation
- Confidential investigations
- High-availability security operations

## Dependency Security

Dependencies should be kept reasonably current and reviewed before major releases.

Deprecation warnings do not necessarily indicate exploitable vulnerabilities, but security advisories affecting project dependencies should be evaluated when discovered.

Automated regression testing should be performed after security-sensitive dependency changes.

Run the complete test suite with:

```bash
PYTHONPATH="$PWD" python -m pytest -q
```

The current release regression result is:

```text
497 passed
0 failed
```

## Responsible Disclosure

Please allow reasonable time to investigate and remediate a reported security issue before publishing technical details.

Good-faith defensive security research and responsible disclosure are welcomed.

Testing must remain limited to systems, accounts, data, and infrastructure that the researcher is authorized to access.

Do not use vulnerability research against MailScope AI as authorization to test third-party systems or services.

## Scope of the Public Release

The public MailScope AI portfolio release demonstrates:

- Email and URL threat analysis
- Identity intelligence
- Threat enrichment
- Evidence-grounded investigation reporting
- Campaign detection
- Threat hunting
- Case management
- Threat graphs
- SOC Copilot

Enterprise production controls such as centralized authentication, RBAC, managed secrets, high availability, enterprise audit infrastructure, SIEM/SOAR integration, and compliance-specific controls are future work.

## Security Contact

When available, use the repository's **GitHub Private Vulnerability Reporting** feature for security reports.

Do not post credentials, active secrets, private user data, or sensitive exploit details in public GitHub issues.

## Security Disclaimer

MailScope AI assists defensive security analysis but does not guarantee detection of every phishing attempt or malicious artifact.

A low-risk result should not be interpreted as proof that an email, URL, attachment, domain, or sender is safe.

A high-risk result should likewise be reviewed in context before consequential response actions are taken.

Human analyst judgment and additional organizational security controls remain important for high-impact decisions.
