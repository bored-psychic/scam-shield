#!/usr/bin/env bash
# One-command dev start: refreshes stale link lists (never blocking on the network), then runs the API (8000) and the frontend (5173).
# Usage: ./run.sh [--skip-update | --force-update]     Downloads happen only in src/update_link_lists.py; the app itself never downloads.
set -u
cd "$(dirname "$0")"
LISTS=data/final/linklists
MAX_AGE=$((24 * 3600))
UPDATE_TIMEOUT=120
API_PORT=8000
WEB_PORT=5173
mode=auto
case "${1:-}" in
  --skip-update) mode=skip ;;
  --force-update) mode=force ;;
  "") ;;
  *) echo "usage: ./run.sh [--skip-update | --force-update]"; exit 2 ;;
esac

now=$(date +%s)
mtime() { stat -f %m "$1" 2>/dev/null || echo 0; }
age_text() {   # "3 h old", "2 d old", "missing"
  local f="$LISTS/$1"
  [ -f "$f" ] || { echo "missing"; return; }
  local s=$(( now - $(mtime "$f") ))
  if [ "$s" -ge 86400 ]; then echo "$((s / 86400)) d old"
  elif [ "$s" -ge 3600 ]; then echo "$((s / 3600)) h old"
  else echo "$((s / 60)) min old"; fi
}

free_port() {   # stop whatever listens on $1, then wait until it is free
  local port=$1 pids i
  pids=$(lsof -ti tcp:"$port" -sTCP:LISTEN 2>/dev/null)
  [ -n "$pids" ] || return 0
  echo "[run] port $port is in use, stopping: $(echo $pids)"
  kill $pids 2>/dev/null
  for i in 1 2 3 4 5 6 7 8 9 10; do
    lsof -ti tcp:"$port" -sTCP:LISTEN >/dev/null 2>&1 || return 0
    sleep 0.5
  done
  kill -9 $(lsof -ti tcp:"$port" -sTCP:LISTEN 2>/dev/null) 2>/dev/null
  sleep 0.5
  if lsof -ti tcp:"$port" -sTCP:LISTEN >/dev/null 2>&1; then echo "[run] could not free port $port"; exit 1; fi
}

# ---- 1. ports
free_port $API_PORT
free_port $WEB_PORT

# ---- 2. link lists
# file per step; URLhaus needs a key at download time, without it that list is skipped and kept as it is (and does not count as stale)
steps=(tranco openphish rdap_bootstrap ip2asn)
files=(tranco_top1m.csv openphish.txt rdap_dns.json ip2asn-v4.tsv.gz)
if [ -n "${URLHAUS_AUTH_KEY:-}" ]; then
  steps+=(urlhaus); files+=(urlhaus_recent.csv)
else
  echo "[run] warning: URLHAUS_AUTH_KEY is not set, the URLhaus list is not refreshed (the existing file is kept)"
fi
stale=0
for f in "${files[@]}"; do
  if [ ! -f "$LISTS/$f" ] || [ $(( now - $(mtime "$LISTS/$f") )) -gt $MAX_AGE ]; then stale=1; fi
done
if [ "$mode" = skip ]; then
  echo "[run] --skip-update: lists not refreshed"
elif [ "$mode" = force ] || [ "$stale" = 1 ]; then
  echo "[run] refreshing link lists (up to ${UPDATE_TIMEOUT}s) ..."
  .venv/bin/python src/update_link_lists.py --only "${steps[@]}" &
  upd=$!
  ( sleep $UPDATE_TIMEOUT; kill "$upd" 2>/dev/null ) >/dev/null 2>&1 &
  wd=$!
  wait "$upd" 2>/dev/null; rc=$?
  kill "$wd" 2>/dev/null; wait "$wd" 2>/dev/null
  if [ "$rc" -ne 0 ]; then
    d=$(stat -f %Sm -t %Y-%m-%d "$LISTS/openphish.txt" 2>/dev/null || echo "unknown date")
    echo "[run] WARNING: Lists not refreshed — using lists from $d"
  fi
else
  echo "[run] link lists are less than 24 h old, not refreshed"
fi

# ---- 3. start both, prefixed; Ctrl+C stops both
prefix() { while IFS= read -r line; do printf '[%s] %s\n' "$1" "$line"; done; }
api_pid=""; web_pid=""
cleanup() {
  trap '' INT TERM EXIT
  echo; echo "[run] stopping ..."
  for p in $api_pid $web_pid; do pkill -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; done
  for port in $API_PORT $WEB_PORT; do kill $(lsof -ti tcp:"$port" -sTCP:LISTEN 2>/dev/null) 2>/dev/null; done
  sleep 1
  for port in $API_PORT $WEB_PORT; do kill -9 $(lsof -ti tcp:"$port" -sTCP:LISTEN 2>/dev/null) 2>/dev/null; done
  wait 2>/dev/null
  exit 0
}
trap cleanup INT TERM EXIT

.venv/bin/uvicorn shield.api.main:app --host 127.0.0.1 --port $API_PORT > >(prefix api) 2>&1 &
api_pid=$!
(cd frontend && exec npm run dev -- --host 0.0.0.0) > >(prefix web) 2>&1 &
web_pid=$!

# ---- 4. once the backend is healthy
for i in $(seq 1 120); do
  curl -sf "http://127.0.0.1:$API_PORT/api/health" >/dev/null 2>&1 && break
  kill -0 "$api_pid" 2>/dev/null || { echo "[run] the API stopped; see [api] lines above"; exit 1; }
  sleep 0.5
done
ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)
now=$(date +%s)
echo "[run] ready"
echo "[run]   this Mac: http://127.0.0.1:$WEB_PORT"
[ -n "$ip" ] && echo "[run]   phone:    http://$ip:$WEB_PORT   (same Wi-Fi)" || echo "[run]   phone:    no Wi-Fi IP found"
echo "[run]   lists: URLhaus: $(age_text urlhaus_recent.csv), OpenPhish: $(age_text openphish.txt), Tranco: $(age_text tranco_top1m.csv)"
wait
