# v0cday master in production

`docker-compose.prod.yml` runs the platform behind **one** entry point: Caddy,
on ports 80 and 443, with TLS. Nothing else is reachable from the network:

| Service | Reachable from |
|---|---|
| `web` (Caddy: UI, API, probe API) | the network, 80 → redirect, 443 |
| `backend` (API) | Caddy, and `127.0.0.1:8888` on the host (health checks, bootstrap) |
| `db`, `redis`, `neo4j` | the containers only — Redis requires a password |

The API runs with `APP_ENV=production` and **refuses to start** with a default
`SECRET_KEY` or password, `CORS_ORIGINS=*`, a non-`https://` `PUBLIC_URL`, or
`PROBE_REQUIRE_HTTPS=false`. The log says which setting to fix.

## Install

On a Linux host with Docker and the Compose plugin, as a user in the `docker`
group:

```sh
DEPLOY_STACK=prod PUBLIC_HOST=soc.example scripts/deploy.sh "$PWD"
```

The script creates `~/v0cday/.env` with random secrets on the first run (and
adds `REDIS_PASSWORD`, `PUBLIC_HOST`, `CORS_ORIGINS`, `PUBLIC_URL` to an
existing one), builds the images, starts the stack and waits for the API. The
admin password is `DEFAULT_ADMIN_PASSWORD` in that `.env`.

From the self-hosted GitHub runner: set the repository variable
`DEPLOY_STACK=prod` (Settings › Secrets and variables › Actions › Variables).

Switching an existing installation from the development stack keeps the data
(same project name and volumes); the Vite dev server and the published
database ports go away.

## Certificates

`CADDY_TLS` in `.env`:

- **your e-mail address** — Let's Encrypt certificate for a public domain
  name. Ports 80 and 443 must be reachable from the Internet.
- **`internal`** (default) — Caddy's own CA, for a lab or a bare IP. Browsers
  warn until its root is trusted, and **probes need it** (below).

Root certificate of the internal CA:

```sh
docker compose -f docker-compose.prod.yml exec -T web \
  cat /data/caddy/pki/authorities/local/root.crt > caddy-root.crt </dev/null
```

## Probes

Probes reach the platform at `https://<PUBLIC_HOST>` (the same port 443). With
the internal CA, put `caddy-root.crt` in the probe's `deploy/probe/config/` as
`ca.pem`, and enroll with:

```sh
docker compose run --rm probe enroll --platform https://<PUBLIC_HOST> \
  --token <token> --ca-bundle /etc/v0cday-probe/ca.pem
```

## Firewall

Open 443 (and 80 for Let's Encrypt and the HTTP → HTTPS redirect). Nothing
else needs to be reachable. SSH access to the host is your own policy.

## What stays to do

- Back up the `db_data` volume (and `data/`): see the MSP runbook.
- Client certificates (mTLS) for probes on top of their secret: not yet.
