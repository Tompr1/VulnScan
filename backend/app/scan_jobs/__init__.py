"""
Scan job use case: run a queued scan job, post-process its findings, persist
them and notify integrations.

Split out of the former 777-line ``worker_tasks.run_scan_job`` function:

- ``submission``    — creates and enqueues jobs (used by the HTTP API);
- ``validation``    — validation state carried in a finding's evidence;
- ``filtering``     — which findings are dropped before being saved;
- ``processing``    — turns raw plugin findings into scored, persisted ones;
- ``notifications`` — scan completed / failed messages per integration;
- ``repository``    — persistence port and its SQLAlchemy adapter;
- ``outcome``       — job statuses, failure and completion values;
- ``assignment``    — the job sent to an executor and the report it sends back;
- ``execution``     — runs an assignment, with no database (platform or probe);
- ``executors``     — how each scan type is executed;
- ``progress``      — throttled progress reporting;
- ``ai_trigger``    — automatic AI analysis after a scan;
- ``graph``         — attack-graph publication;
- ``runner``        — orchestration of all of the above.
"""
