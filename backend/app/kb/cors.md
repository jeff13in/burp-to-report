# CORS misconfiguration
Tags: cors, cross-origin resource sharing, origin reflection, credentials, null origin

The server echoes the request Origin into Access-Control-Allow-Origin (or allows the null origin) while also sending Access-Control-Allow-Credentials: true. A malicious site can then read authenticated responses from the victim's browser.

Strong evidence: an untrusted Origin is reflected and credentials are allowed on an endpoint that returns user data.

Weak evidence: reflection without credentials, wildcard (*) without credentials, or endpoints that return only public data.

Severity: High when credentialed reflection exposes account data; Low without credentials.

Remediation: validate Origin against an exact allow-list, never reflect arbitrary origins with credentials, and avoid trusting null.
