# Sensitive data exposure in responses
Tags: sensitive data exposure, secrets, credentials, api key, password hash, PII, OWASP A02 cryptographic failures, API3 excessive data exposure

The API returns more data than the client needs, such as password hashes, plaintext passwords, API keys, cloud credentials, private keys or government identifiers.

Evidence: fields like password_hash, api_key, secret, ssn, or key formats such as AKIA... in a JSON response.

Weakening signals: placeholder or test values, keys documented as public (publishable keys), or data the user is entitled to see about themselves.

Severity: Critical for live credentials or private keys, High for hashes and government ids, Medium for unnecessary PII.

Remediation: filter responses through explicit serializers or allow-lists, never return secrets or hashes, rotate any credential that was exposed.
