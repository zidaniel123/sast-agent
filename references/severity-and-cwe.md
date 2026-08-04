# Severity rubric & CWE mapping

Shared reference for classifying findings. Judge severity by **real
reachability and impact**, not by a raw CVSS base score. A textbook-dangerous
pattern that no untrusted input can reach is not Critical.

## Severity levels

- **Critical** — Reachable by an unauthenticated or low-privilege attacker and
  leads directly to full compromise: remote code execution, authentication
  bypass to admin, mass data exfiltration, or trivial full-account takeover. A
  clean source-to-sink path with no effective sanitization.

- **High** — Reachable and high-impact, but with a meaningful precondition:
  requires authentication, a specific role, or a non-default configuration.
  Examples: authenticated SQL injection, SSRF into internal services, stored
  XSS in a privileged view, arbitrary file write in a constrained path.

- **Medium** — Real but limited impact, or a genuine flaw whose exploitation is
  constrained: reflected XSS needing user interaction, IDOR exposing non-
  sensitive data, missing hardening on a sensitive operation, or a weak but not
  broken control.

- **Low** — Minor issues and defense-in-depth gaps with little standalone
  impact: verbose errors, missing security headers, weak-but-unreachable
  patterns, minor information disclosure.

- **Informational** — Observations worth recording that are not vulnerabilities
  on their own: notable design choices, deprecated dependencies without a known
  reachable exploit, or context that strengthens other findings.

## Confidence

Report `confidence` separately from severity. Confidence reflects how certain
the source-to-sink path is:

- **High** — the full taint path was traced and no effective sanitizer sits on
  it.
- **Medium** — the pattern and likely path are clear, but one hop (reachability
  or a sanitizer's effectiveness) is inferred rather than confirmed.
- **Low** — a suspicious pattern with an unconfirmed path; flagged for human
  review.

## CWE mapping

- Map each finding to the most specific applicable CWE (e.g. `CWE-89` SQL
  injection, `CWE-79` XSS, `CWE-78` OS command injection, `CWE-22` path
  traversal, `CWE-502` deserialization, `CWE-918` SSRF, `CWE-287` improper
  authentication, `CWE-798` hardcoded credentials, `CWE-611` XXE).
- Prefer the specific child CWE over a broad parent when the mechanism is known.
- Use the `CWE-<number>` format.
- When a finding fits multiple CWEs, pick the one that best describes the root
  cause of the traced flow.
