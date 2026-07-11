# Security Policy

AgentSentry is a security product, so we hold this gateway to a higher standard
than the attacks it detects. Thank you for helping keep it trustworthy.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately through **[GitHub Private Vulnerability Reporting](https://github.com/akav-labs/agentsentry-gateway/security/advisories/new)**
(the "Report a vulnerability" button on the Security tab), or email
**security@akav.io**.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a request/response or minimal PoC). **Redact real secrets.**
- The version or image tag / commit affected.

We aim to acknowledge reports within **3 business days**, agree on a disclosure
timeline, and credit reporters who wish to be named.

## What counts as a vulnerability (vs. a detection gap)

This gateway is deterministic, pattern-based detection — it raises the bar, it is
not a guarantee. Please file these as the *right* kind of report:

- **A detection bypass / evasion** (a jailbreak or secret that slips past a rule)
  is a **detection gap**, not a vulnerability. These are genuinely welcome — open
  a normal *"Missed detection / evasion"* issue or a PR. That's how the rules get
  better.
- **A vulnerability** is a flaw in the gateway *itself*: a crash / panic / DoS
  reachable from a request, memory-safety issues, a way to make the gateway
  exfiltrate or mishandle traffic, or anything that breaks the security guarantee
  for reasons other than "a rule didn't match." Please report these privately.

## Supported versions

The latest released version receives security fixes. AgentSentry Gateway is
pre-1.0, so please track the newest tag.

| Version | Supported |
|---------|-----------|
| latest `0.x` | ✅ |
| older       | ❌ |

## Scope

This policy covers the open-source gateway in this repository. For the commercial
AgentSentry platform, contact security@akav.io.
