#!/usr/bin/env bash
# Keep the hosted demo alive from this machine: the release server in demo
# mode, and a Cloudflare quick tunnel in front of it. Quick tunnels get a new
# address whenever they restart, so on every (re)start this writes the current
# URL to .thine/tunnel-url.txt and, if a Lideeyah/redirect Pages repo exists,
# points its index at the new address, giving the outside world one stable
# URL. Run it under launchd with KeepAlive to survive sleeps and reboots, or
# in a terminal for as long as that terminal lives.
set -u
cd "$(dirname "$0")/.."

CLOUDFLARED=/opt/homebrew/opt/cloudflared/bin/cloudflared
SERVER=./target/release/thine-web
LOG=.thine/host-demo.log
# launchd starts agents with a bare PATH, which is how the first repoint
# silently failed to find gh. Absolute paths, with a lookup fallback.
GH=/opt/homebrew/bin/gh
[ -x "$GH" ] || GH=$(command -v gh || true)

ensure_server() {
  if ! curl -s -m 3 http://localhost:8080/api/meta >/dev/null 2>&1; then
    pkill -f "thine-web --demo" 2>/dev/null
    sleep 1
    nohup "$SERVER" --demo --send-rpc https://rpc.testnet.fastnear.com \
      >> "$LOG" 2>&1 &
    for _ in $(seq 1 40); do
      curl -s -m 2 http://localhost:8080/api/meta >/dev/null 2>&1 && break
      sleep 1
    done
  fi
}

publish_url() {
  local url=$1
  echo "$url" > .thine/tunnel-url.txt
  # Best effort: only if the redirect repo exists and gh is authenticated.
  [ -n "$GH" ] || return 0
  "$GH" api repos/Lideeyah/redirect >/dev/null 2>&1 || return 0
  local sha content
  sha=$("$GH" api repos/Lideeyah/redirect/contents/index.html --jq .sha 2>/dev/null)
  content=$(printf '<!doctype html><meta charset="utf-8">\n<meta http-equiv="refresh" content="0; url=%s">\n<title>Continue</title>\n<p><a href="%s">Continue</a></p>\n' "$url" "$url" | base64)
  "$GH" api repos/Lideeyah/redirect/contents/index.html -X PUT \
    -f message="point at the current demo" \
    -f content="$content" ${sha:+-f sha="$sha"} >/dev/null 2>&1 \
    && echo "$(date -u +%FT%TZ) redirect -> $url" >> "$LOG"
}

while true; do
  ensure_server
  rm -f .thine/tunnel.log
  "$CLOUDFLARED" tunnel --url http://localhost:8080 > .thine/tunnel.log 2>&1 &
  TUNNEL_PID=$!
  for _ in $(seq 1 60); do
    URL=$(grep -oE "https://[a-z0-9-]+\.trycloudflare\.com" .thine/tunnel.log | head -1)
    [ -n "${URL:-}" ] && break
    sleep 1
  done
  [ -n "${URL:-}" ] && publish_url "$URL"
  wait "$TUNNEL_PID"
  echo "$(date -u +%FT%TZ) tunnel exited; restarting" >> "$LOG"
  sleep 3
done
