"""
Scan probes: VMs installed on clients' networks that run the clients' scans.

A probe only ever connects out to the platform (the client opens no port):
it enrolls once with a one-time token, then signs in with its own secret to
claim the client's jobs routed to probes, report progress and send results.

- ``secrets``   — enrollment tokens and probe secrets (stored as digests);
- ``placement`` — which of a client's scan types run on its probe;
- ``registry``  — probes of the clients: create, enroll, authenticate, revoke;
- ``jobs``      — jobs as a probe sees them: claim the next one, own one.
"""
