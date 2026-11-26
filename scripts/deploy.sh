#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# v0cday — deploys the checked-out commit on this host.
# Run by the self-hosted GitHub Actions runner (.github/workflows/deploy.yml),
# and can be run by hand the same way.
#
# Usage:   scripts/deploy.sh <source-dir>
#            <source-dir>  checkout of the commit to deploy (the CI workspace)
#
# Env:     DEPLOY_DIR              install directory        (default: ~/v0cday)
#          PUBLIC_HOST             address used in URLs/CORS (default: first host IP)
#          HEALTH_TIMEOUT_SECONDS  wait for the backend      (default: 900)
#          DEPLOY_STACK            dev  — docker-compose.yml: Vite dev server on
#                                         :5173, API on :8888 (default)
#                                  prod — docker-compose.prod.yml: HTTPS on 443
#                                         through Caddy, nothing else exposed
#
# What survives a deploy: .env (created once, with random secrets) and data/
# (datasets, reports). Everything else is replaced by the deployed commit.
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

SOURCE_DIR="${1:?usage: scripts/deploy.sh <source-dir>}"
DEPLOY_DIR="${DEPLOY_DIR:-$HOME/v0cday}"
PUBLIC_HOST="${PUBLIC_HOST:-$(hostname -I | awk '{print $1}')}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-900}"
DEPLOY_STACK="${DEPLOY_STACK:-dev}"
case "$DEPLOY_STACK" in
  dev)  COMPOSE_FILE_NAME=docker-compose.yml ;;
  prod) COMPOSE_FILE_NAME=docker-compose.prod.yml ;;
  *)    printf 'ERROR: DEPLOY_STACK must be dev or prod, not %s\n' "$DEPLOY_STACK" >&2; exit 1 ;;
esac
BOOTSTRAP_MARKER="$DEPLOY_DIR/.bootstrapped"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_commands() {
  local cmd
  for cmd in docker rsync curl openssl python3; do
    command -v "$cmd" >/dev/null || die "missing command: $cmd"
  done
  docker info >/dev/null 2>&1 || die "cannot talk to Docker (is $(whoami) in the docker group?)"
}

# Docker networks default to MTU 1500. On a host whose uplink has a smaller
# MTU (VPN, some hypervisors), large packets from containers are dropped:
# HTTPS from the image build hangs, then fails with "Connection reset by peer".
check_docker_mtu() {
  local iface mtu
  iface=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
  [[ -n "$iface" && -r "/sys/class/net/$iface/mtu" ]] || return 0
  mtu=$(cat "/sys/class/net/$iface/mtu")
  if ((mtu < 1500)) && ! grep -q '"mtu"' /etc/docker/daemon.json 2>/dev/null; then
    die "$iface has MTU $mtu but Docker uses 1500: container HTTPS will hang. Put
  {\"mtu\": $mtu, \"default-network-opts\": {\"bridge\": {\"com.docker.network.driver.mtu\": \"$mtu\"}}}
in /etc/docker/daemon.json, then: sudo systemctl restart docker"
  fi
}

sync_code() {
  log "Syncing $SOURCE_DIR -> $DEPLOY_DIR"
  # data/ is created here, as the current user: if Docker created it for the
  # bind mount it would be owned by root.
  mkdir -p "$DEPLOY_DIR/data"
  rsync -a --delete \
    --exclude '/.env' \
    --exclude '/data/' \
    --exclude '/.bootstrapped' \
    --exclude '/.deployed-commit' \
    --exclude '.git/' \
    --exclude 'node_modules/' \
    --exclude '__pycache__/' \
    --exclude '.pytest_cache/' \
    "$SOURCE_DIR"/ "$DEPLOY_DIR"/
}

create_env_file() {
  local env_file="$DEPLOY_DIR/.env"
  [[ -f "$env_file" ]] && return 0
  refuse_stale_volumes

  log "First deploy: creating .env with random secrets"
  local db_password neo4j_password admin_password origin
  db_password=$(openssl rand -hex 16)
  neo4j_password=$(openssl rand -hex 16)
  admin_password=$(openssl rand -hex 12)
  origin="http://$PUBLIC_HOST:5173,http://localhost:5173"
  [[ "$DEPLOY_STACK" == prod ]] && origin="https://$PUBLIC_HOST"
  sed \
    -e "s|^SECRET_KEY=.*|SECRET_KEY=$(openssl rand -hex 32)|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$db_password|" \
    -e "s|^DATABASE_URL=.*|DATABASE_URL=postgresql+psycopg2://app:$db_password@db:5432/app|" \
    -e "s|^NEO4J_PASSWORD=.*|NEO4J_PASSWORD=$neo4j_password|" \
    -e "s|^NEO4J_AUTH=.*|NEO4J_AUTH=neo4j/$neo4j_password|" \
    -e "s|^DEFAULT_ADMIN_PASSWORD=.*|DEFAULT_ADMIN_PASSWORD=$admin_password|" \
    -e "s|^CORS_ORIGINS=.*|CORS_ORIGINS=$origin|" \
    "$DEPLOY_DIR/.env.example" > "$env_file"
  chmod 600 "$env_file"
  # The password is never printed: CI logs are visible on GitHub.
  echo "Admin account: $(env_value DEFAULT_ADMIN_EMAIL) — password: DEFAULT_ADMIN_PASSWORD in $env_file"
}

# Postgres and Neo4j only read their password when their volume is first
# initialised. Volumes left by a previous install keep the old passwords, so
# the random ones of a new .env would be rejected ("password authentication
# failed"). Stop before creating .env and say how to proceed.
refuse_stale_volumes() {
  local project stale
  project=$(awk '/^name:/ {print $2; exit}' "$DEPLOY_DIR/docker-compose.yml")
  stale=$(docker volume ls -q | grep -E "^${project}_(db|neo4j)_data$" || true)
  [[ -z "$stale" ]] && return 0
  die "volumes from a previous installation exist: $(echo "$stale" | xargs)
They keep their own database passwords, so a freshly generated .env cannot connect. Either:
  - start from scratch (DELETES their data):  docker volume rm $(echo "$stale" | xargs)
  - or keep the data: create $env_file yourself from .env.example with the previous passwords
Then re-run the deployment."
}

env_value() {
  grep -E "^$1=" "$DEPLOY_DIR/.env" | tail -n1 | cut -d= -f2-
}

# Sets KEY=VALUE in .env (replacing an existing line, empty or not).
set_env_value() {
  local env_file="$DEPLOY_DIR/.env"
  if grep -qE "^$1=" "$env_file"; then
    sed -i "s|^$1=.*|$1=$2|" "$env_file"
  else
    printf '%s=%s\n' "$1" "$2" >> "$env_file"
  fi
}

# Values every deploy needs, added to an .env created by an older version.
# The production stack also serves the UI over HTTPS on PUBLIC_HOST.
complete_env_file() {
  if [[ -z "$(env_value REDIS_PASSWORD)" ]]; then
    log "Adding a random REDIS_PASSWORD to .env"
    set_env_value REDIS_PASSWORD "$(openssl rand -hex 24)"
  fi
  [[ "$DEPLOY_STACK" == prod ]] || return 0
  if [[ "$(env_value PUBLIC_HOST)" != "$PUBLIC_HOST" ]]; then
    log "Production: UI and API at https://$PUBLIC_HOST"
    set_env_value PUBLIC_HOST "$PUBLIC_HOST"
    set_env_value CORS_ORIGINS "https://$PUBLIC_HOST"
    set_env_value PUBLIC_URL "https://$PUBLIC_HOST"
  fi
}

start_stack() {
  log "Building and starting containers (the first build takes several minutes)"
  cd "$DEPLOY_DIR"
  # --remove-orphans: switching stacks removes the other one's services
  # (the data volumes are shared and kept).
  docker compose -f "$COMPOSE_FILE_NAME" up -d --build --remove-orphans
}

wait_for_backend() {
  local url="http://localhost:${BACKEND_PORT}/healthz"
  local deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))
  log "Waiting for $url"
  until curl -fsS -o /dev/null "$url"; do
    if ((SECONDS >= deadline)); then
      docker compose -f "$COMPOSE_FILE_NAME" ps
      docker compose -f "$COMPOSE_FILE_NAME" logs --tail 100 backend
      die "backend not healthy after ${HEALTH_TIMEOUT_SECONDS}s"
    fi
    sleep 5
  done
}

bootstrap_once() {
  [[ -f "$BOOTSTRAP_MARKER" ]] && return 0
  log "First deploy: creating default profiles, credentials and datasets"
  (
    set -a
    # shellcheck source=/dev/null
    source "$DEPLOY_DIR/.env"
    set +a
    API_BASE="http://localhost:${BACKEND_PORT}" ./bootstrap.sh --no-up
  )
  touch "$BOOTSTRAP_MARKER"
}

main() {
  require_commands
  check_docker_mtu
  sync_code
  create_env_file
  complete_env_file
  BACKEND_PORT=$(env_value BACKEND_PORT); BACKEND_PORT=${BACKEND_PORT:-8888}
  FRONTEND_PORT=$(env_value FRONTEND_PORT); FRONTEND_PORT=${FRONTEND_PORT:-5173}
  start_stack
  wait_for_backend
  bootstrap_once
  local commit
  commit=$(git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null || echo "unknown commit")
  echo "$commit" > "$DEPLOY_DIR/.deployed-commit"
  docker image prune -f >/dev/null

  log "Deployed $commit ($DEPLOY_STACK stack)"
  if [[ "$DEPLOY_STACK" == prod ]]; then
    echo "  Platform : https://$PUBLIC_HOST  (UI, API and probe API)"
  else
    echo "  Frontend : http://$PUBLIC_HOST:$FRONTEND_PORT"
    echo "  API      : http://$PUBLIC_HOST:$BACKEND_PORT"
  fi
}

main "$@"
