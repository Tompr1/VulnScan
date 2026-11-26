# v0cday scan probe

A probe is a VM in a client's network that runs the client's scans for the
platform. It **only connects out** to the platform over HTTPS: the client
opens no inbound port. It needs outbound access to:

- the platform (`https://<platform>`), port 443;
- the scan targets, inside the client's network;
- for an image build only: Debian, PyPI, GitHub and Docker Hub.

## 1. Create the probe on the platform

As a super admin, in **Root › Scan probes**: *New probe*, choose the client,
name the site. Copy the enrollment command shown: the token works **once**
and expires (24 h by default). Then tick, for that client, the scan types its
probe runs (*Where each client's scans run*).

## 2. Install on the VM

Any Linux VM with Docker and the Compose plugin:

```sh
git clone <this repository> v0cday && cd v0cday/deploy/probe
docker compose build
```

## 3. Enroll

```sh
docker compose run --rm probe enroll --platform https://soc.example --token <token>
```

Options:

- `--ca-bundle /etc/v0cday-probe/ca.pem` — trust a private CA (put the file
  in `./config/`);
- `--local-allowlist "10.0.0.0/8,.corp.local"` — the **client's own limit**:
  the probe refuses any job outside it, whatever the platform asks
  (same syntax as `ALLOWLIST`; external scans are not limited by it);
- `--allow-http` — lab only, platform without TLS (the platform must then
  run with `PROBE_REQUIRE_HTTPS=false`).

The configuration, with the probe's credential, is written to
`./config/probe.json`, readable by its owner only.

## 4. Run

```sh
docker compose up -d
docker compose logs -f probe
docker compose run --rm probe status    # connection check
```

The probe appears **online** in Root › Scan probes. It takes one job at a
time; a finished scan's report is kept in the `probe-state` volume until the
platform accepts it, so a network cut or a restart loses nothing.

## Revocation, reinstallation

- **Revoke** in Root: the probe stops at its next call (`run` exits with
  code 2). A revoked probe cannot be enrolled again: create a new one.
- **Reinstalled VM**: *New enrollment token* (key icon) in Root, then enroll
  again; the previous installation's credential stops working.
