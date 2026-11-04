# Verbose error messages and stack traces
Tags: information disclosure, stack trace, debug mode, sql error, OWASP A05 security misconfiguration

The server returns internal error details: stack traces, file paths, framework versions, SQL error text or database driver messages.

Why it matters: it reveals technology, versions and file layout, and SQL error text can indicate that input reaches a query unsafely, which a tester should investigate separately as a possible injection.

Evidence: exception class names, file:line references, SQLSTATE or ORA- codes in a response body.

Severity: usually Low or Informational on its own; raise it if the message exposes secrets or confirms an injection point.

Remediation: disable debug mode in production, return generic error messages, and log details server-side only.
