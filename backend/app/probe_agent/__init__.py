"""
The scan probe agent: what runs on a probe VM in a client's network.

It only ever connects out to the platform (``/probe/v1``):

    v0cday-probe enroll --platform URL --token T   once, saves the credential
    v0cday-probe run                                then forever:
        wait for a job -> run it with the scan engine -> send progress
        (stop when told) -> send the report (kept on disk until accepted)

- ``config``    — the probe's configuration file (credential, platform URL,
                  the client's own scope limit);
- ``platform``  — HTTP client of the platform's probe API;
- ``reference`` — reference data (CVE catalog, KEV…) read from the platform,
                  cached on disk;
- ``agent``     — runs jobs and reports them;
- ``cli``       — the ``v0cday-probe`` command.

Nothing here touches a database or the platform's secret key: the job
brings its credentials, the platform answers the rest.
"""
