# Severity rating guide
Tags: severity, cvss, impact, likelihood, bug bounty triage, priority

Rate severity on impact and exploitability, not on how interesting the bug is.
Critical: unauthenticated or low-effort access to many users' sensitive data, account takeover, live credential exposure, remote code execution.
High: reading or modifying other users' private data (IDOR on PII), credentialed CORS on account data, auth bypass on a sensitive function.
Medium: reflected XSS needing interaction, limited data exposure, issues needing an unusual precondition.
Low: verbose errors, version disclosure, best-practice gaps without demonstrated impact.
Informational: observations worth noting with no direct security impact.
Always state the precondition (authenticated? which role? user interaction?) and the data or action affected.
