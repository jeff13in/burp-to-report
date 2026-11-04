# Missing authentication or authorization on an API route
Tags: missing authorization, unauthenticated access, broken access control, OWASP A01, API5 broken function level authorization

The route returns protected data or performs a privileged action when the request carries no session cookie or Authorization header, or when a low-privilege user calls an administrative function.

Evidence: a request with no credentials receives 2xx and a body containing user records, roles, emails or admin-only data; the same route is called with a token elsewhere in the traffic, suggesting the client assumes it is protected.

Weakening signals: the data is intentionally public, the response is an empty or generic payload, or a redirect to login is returned with a 200 status.

Severity: High to Critical depending on data sensitivity and whether state can be changed.

Remediation: apply authentication middleware by default (deny unless allowed), and check role or permission for each function, not only in the UI.
