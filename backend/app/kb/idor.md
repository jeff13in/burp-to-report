# Insecure direct object reference (IDOR)
Tags: idor, broken access control, object id, horizontal privilege escalation, OWASP A01

An IDOR exists when an application uses an identifier supplied by the client (a numeric id, UUID or filename) to fetch an object and does not check that the current user is allowed to access that object. Typical evidence: a session belonging to user A requests /api/users/B or /orders/B and the server answers 200 with B's data.

Signals that strengthen the case: the authenticated identity (JWT sub claim, session user id) differs from the object's owner field; responses for different ids contain different emails or owner ids under the same session.

Signals that weaken it: the object is public by design (product pages, public profiles), the endpoint returns 403/404 for foreign ids, or both ids belong to the same user.

Severity: usually High when personal data is read, Critical when objects can be modified or deleted or when financial data is exposed. Confirm with two accounts you control.

Remediation: enforce object-level authorization on every request on the server side, deriving ownership from the session rather than from client input. Prefer scoped queries (WHERE owner_id = current_user).
