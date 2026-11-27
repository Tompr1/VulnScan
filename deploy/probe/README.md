# v0cday scan probe

A probe is a VM in a client's network that runs the client's scans and host
discoveries for the platform. It **only connects out** to the platform over
HTTPS: the client opens no inbound port. It needs outbound access to:

- the platform (`https://<platform>`), port 443;
- the scan targets and the ranges to discover, inside the client's network;
- for an image build only: Debian, PyPI, GitHub and Docker Hub.

## What runs on the probe

| Job | Where it runs |
|---|---|
| Internal network and API scans | On the probe **by default**, as soon as the client has an enrolled probe. |
| External / web scans | On the platform by default (they test the client from the Internet); tick them in Root to run them from the probe. |
| Host discovery (*Analytics › Asset Discovery*, a CIDR range) | **Only** on the probe. A client without an enrolled probe cannot discover hosts. |
| IaC, device inventory (Intune) | Always on the platform. |

Root can change the scan types per client in **Root › Scan probes › Where each
client's scans run**; the client shows *default* until someone does. A list
saved there (even an empty one) is kept as is.

## 1. Create the probe on the platform

As a super admin, in **Root › Scan probes**: *New probe*, choose the client,
name the site. Copy the enrollment command shown: the token works **once**
and expires (24 h by default).

Nothing else to set: once the probe is enrolled, the client's internal and API
scans and its host discoveries go to it (see the table above). Before that,
they keep running on the platform, and discovery is refused.

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
  (same syntax as `ALLOWLIST`; external scans are not limited by it). A range
  to discover must fit entirely inside one of its networks;
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
time, a waiting discovery first (someone is watching it on the page); a
finished scan's or discovery's report is kept in the `probe-state` volume
until the platform accepts it, so a network cut or a restart loses nothing.

## Host discovery

A user starts it in *Analytics › Asset Discovery* with a private range
(`192.168.10.0/24`). The platform accepts it only if the client has an enrolled
probe and the range fits inside the client's allowlist; the probe checks the
range again against that allowlist and its own `--local-allowlist`.

The probe then tries a TCP connection to ports 22, 80, 443, 445, 3389 and 8080
of each address, 256 addresses at a time (no root, no raw packets): an address
that accepts or refuses one counts as a live host, named by reverse DNS. After
each wave it sends the hosts found so far, so the page fills in as it goes. It
stops when the user cancels, or after `DISCOVERY_BUDGET_SECONDS` (1 h by
default, set on the platform), keeping the hosts already found. Hosts that drop
every probe silently are not seen.

## Update

```sh
git pull && docker compose build && docker compose up -d
```

Host discovery needs a probe built from this version or later: an older probe
keeps running scans but never takes a discovery, which then fails after 30 min
(`DISCOVERY_UNCLAIMED_AFTER_SECONDS`) with a message asking to check the probe.
Appliances update themselves when the platform publishes a new `PROBE_IMAGE`
(`deploy/appliance/README.md`).

## Revocation, reinstallation

- **Revoke** in Root: the probe stops at its next call (`run` exits with
  code 2). A revoked probe cannot be enrolled again: create a new one.
- **Reinstalled VM**: *New enrollment token* (key icon) in Root, then enroll
  again; the previous installation's credential stops working.
