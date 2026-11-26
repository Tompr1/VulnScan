#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# v0cday Platform — Auto-Updater Service
# Watches for update-trigger.json and runs git pull + docker rebuild.
# Auto-detects project directory from script location.
# ═══════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$(dirname "$SCRIPT_DIR")"
WATCH_DIR="$PROJECT/data"
TRIGGER="$WATCH_DIR/update-trigger.json"
RESULT="$WATCH_DIR/update-result.json"
LOG="/var/log/v0cday-update.log"

# Updates come from this GitHub repository (owner/name), not from whatever
# remote the install was cloned from. Override with GITHUB_REPO in .env.
GITHUB_REPO="$(grep -E '^GITHUB_REPO=' "$PROJECT/.env" 2>/dev/null | tail -n1 | cut -d= -f2-)"
GITHUB_REPO="${GITHUB_REPO:-Tompr1/VulnScan}"
REPO_URL="https://github.com/${GITHUB_REPO}.git"

# Ensure data directory exists
mkdir -p "$WATCH_DIR"

echo "[$(date)] v0cday updater started" >> "$LOG"
echo "[$(date)] Project directory: $PROJECT" >> "$LOG"
echo "[$(date)] Watching: $TRIGGER" >> "$LOG"
echo "[$(date)] Update source: $REPO_URL" >> "$LOG"

write_status() {
    local status="$1"
    local message="$2"
    echo "{\"status\":\"${status}\",\"message\":\"${message}\",\"updated_at\":\"$(date -Iseconds)\"}" > "$RESULT"
}

while true; do
    if [ -f "$TRIGGER" ]; then
        echo "" >> "$LOG"
        echo "═══════════════════════════════════════════════════" >> "$LOG"
        echo "[$(date)] Update triggered" >> "$LOG"

        # Remove trigger immediately to prevent re-processing
        rm -f "$TRIGGER"

        # Phase 1: Git pull
        write_status "updating" "Pulling latest code from GitHub..."
        echo "[$(date)] Phase 1: git pull" >> "$LOG"
        cd "$PROJECT"

        # Use -c safe.directory to bypass ownership check (systemd runs as root, repo owned by ubuntu)
        GIT="git -c safe.directory=$PROJECT"

        # Backup .env before reset (user config must survive)
        cp -f "$PROJECT/.env" "$PROJECT/.env.bak" 2>/dev/null

        # Step 1: Fetch latest from the update repository
        $GIT fetch "$REPO_URL" main >> "$LOG" 2>&1
        FETCH_RC=$?
        echo "[$(date)] git fetch $REPO_URL main (rc=$FETCH_RC)" >> "$LOG"
        if [ $FETCH_RC -ne 0 ]; then
            echo "[$(date)] ERROR: git fetch failed (rc=$FETCH_RC)" >> "$LOG"
            [ -f "$PROJECT/.env.bak" ] && cp -f "$PROJECT/.env.bak" "$PROJECT/.env" && rm -f "$PROJECT/.env.bak"
            write_status "failed" "Git fetch failed (rc=$FETCH_RC). Check credentials or network."
            continue
        fi

        # Step 2: Hard reset to match the fetched commit exactly
        $GIT reset --hard FETCH_HEAD >> "$LOG" 2>&1
        RESET_RC=$?
        echo "[$(date)] git reset --hard FETCH_HEAD (rc=$RESET_RC)" >> "$LOG"
        if [ $RESET_RC -ne 0 ]; then
            echo "[$(date)] ERROR: git reset failed (rc=$RESET_RC)" >> "$LOG"
            [ -f "$PROJECT/.env.bak" ] && cp -f "$PROJECT/.env.bak" "$PROJECT/.env" && rm -f "$PROJECT/.env.bak"
            write_status "failed" "Git reset failed (rc=$RESET_RC). Check $LOG for details."
            continue
        fi

        # Step 3: Clean untracked files (preserve .env and data/)
        $GIT clean -fdx --exclude=.env --exclude=.env.bak --exclude=data/ >> "$LOG" 2>&1
        CLEAN_RC=$?
        echo "[$(date)] git clean (rc=$CLEAN_RC)" >> "$LOG"

        # Restore user's .env (preserve their config)
        if [ -f "$PROJECT/.env.bak" ]; then
            cp -f "$PROJECT/.env.bak" "$PROJECT/.env"
            rm -f "$PROJECT/.env.bak"
            echo "[$(date)] Restored user .env config" >> "$LOG"
        fi

        if [ $CLEAN_RC -ne 0 ]; then
            echo "[$(date)] WARNING: git clean failed (rc=$CLEAN_RC), continuing anyway" >> "$LOG"
        fi
        echo "[$(date)] Git update succeeded" >> "$LOG"

        # Phase 2: Docker build
        write_status "updating" "Rebuilding Docker containers..."
        echo "[$(date)] Phase 2: docker compose build" >> "$LOG"
        docker compose build >> "$LOG" 2>&1
        BUILD_RC=$?

        if [ $BUILD_RC -ne 0 ]; then
            echo "[$(date)] ERROR: docker compose build failed (rc=$BUILD_RC)" >> "$LOG"
            write_status "failed" "Docker build failed (rc=$BUILD_RC). Check $LOG for details."
            continue
        fi
        echo "[$(date)] docker compose build succeeded" >> "$LOG"

        # Phase 3: Restart services
        write_status "updating" "Restarting services..."
        echo "[$(date)] Phase 3: docker compose up -d" >> "$LOG"
        docker compose up -d >> "$LOG" 2>&1
        UP_RC=$?

        if [ $UP_RC -ne 0 ]; then
            echo "[$(date)] ERROR: docker compose up failed (rc=$UP_RC)" >> "$LOG"
            write_status "failed" "Container restart failed (rc=$UP_RC). Check $LOG for details."
            continue
        fi

        echo "[$(date)] Update complete!" >> "$LOG"
        echo "═══════════════════════════════════════════════════" >> "$LOG"

        write_status "success" "Update complete. Platform restarted successfully."
    fi

    sleep 5
done
