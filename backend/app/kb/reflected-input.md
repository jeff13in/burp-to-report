# Reflected input and cross-site scripting (XSS)
Tags: reflected xss, cross-site scripting, output encoding, OWASP A03 injection

User-controlled input is copied into the response. It becomes reflected XSS when the response is rendered as HTML and the input is not encoded for its context, so characters like < > " ' survive and can form markup or script.

Strong evidence: special characters from a parameter appear unencoded in an HTML response (Content-Type text/html). Weak evidence: alphanumeric reflection only, JSON responses with correct Content-Type, or values that are HTML-entity encoded (&lt; &quot;).

A tester must confirm in a browser that script execution is possible in the reflection context (element body, attribute, script block, URL).

Severity: Medium for reflected XSS requiring user interaction; High if it reaches an authenticated, sensitive page or bypasses CSP.

Remediation: context-aware output encoding through the template engine, avoid building HTML by string concatenation, and deploy a strict Content-Security-Policy as defense in depth.
