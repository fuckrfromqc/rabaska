#!/usr/bin/env bash
# What is the live origin actually serving right now?
#
# The build hash in a deploy log is the hash that was uploaded, not the hash
# anyone receives. A stale edge, a header that did not take, or a domain
# pointing somewhere else all look identical to a successful deploy from the
# inside. This asks the origin instead.
#
#   tools/probe.sh https://rabaska.favreau.xyz [expected-build-hash]
#
# Exits non-zero if an expected hash is given and the origin disagrees.
set -uo pipefail

URL="${1:-https://rabaska.favreau.xyz}"
WANT="${2:-}"

echo "probing $URL"
echo

hash_from() { grep -oE "BUILD = ['\"][0-9a-f]{16}['\"]" | grep -oE '[0-9a-f]{16}' | head -1; }

LIVE_APP=$(curl -sS --compressed --max-time 30 "$URL/app.js" | hash_from)
LIVE_SW=$(curl -sS --compressed --max-time 30 "$URL/sw.js" | hash_from)

echo "=== build hash the origin serves ==="
echo "  app.js: ${LIVE_APP:-<none>}"
echo "  sw.js:  ${LIVE_SW:-<none>}"
[ -n "$WANT" ] && echo "  wanted: $WANT"
echo

echo "=== the two CSPs, which must differ (DEPLOY.md 2.5) ==="
# The count matters as much as the content. Cloudflare appends repeated headers
# across matching _headers rules, and a response carrying two policies is
# governed by both at once — so a second CSP can only narrow the first, never
# widen it. A /sw.js rule granting connect-src 'self' underneath a /* rule
# saying 'none' therefore grants nothing, the precache cannot fetch, and the
# app has no offline support. That shipped, and nothing in the build or the
# local server could see it, because both merged the rules into one header.
CSP_DOUBLED=0
for f in / /sw.js; do
  printf '  %-8s ' "$f"
  HDRS=$(curl -sSI --max-time 30 "$URL$f" | tr -d '\r' | grep -ci '^content-security-policy')
  curl -sSI --max-time 30 "$URL$f" | tr -d '\r' \
    | grep -i '^content-security-policy' | tr ';' '\n' \
    | grep -iE 'connect-src' | paste -sd ' ' - | sed 's/^/ /'
  if [ "$HDRS" -ne 1 ]; then
    echo "    ^ $HDRS Content-Security-Policy headers on $f; exactly one is allowed"
    CSP_DOUBLED=1
  fi
  echo
done
echo

echo "=== caching, which is what makes a good deploy look stuck ==="
for f in / /sw.js /app.js /style.css; do
  printf '  %-11s' "$f"
  curl -sSI --max-time 30 "$URL$f" | tr -d '\r' \
    | grep -iE '^(cache-control|age|cf-cache-status|etag)' \
    | paste -sd '; ' - | sed 's/^/ /'
  echo
done
echo

RC=0
if [ "$CSP_DOUBLED" -eq 1 ]; then
  echo "BROKEN: a document is served more than one CSP. Browsers enforce every"
  echo "policy on a response, so the effective one is their intersection. If the"
  echo "worker inherits connect-src 'none' its precache cannot fetch and the app"
  echo "has no offline support, with no error anywhere in the page."
  RC=1
fi

if [ -n "$WANT" ]; then
  if [ "$LIVE_APP" = "$WANT" ] && [ "$LIVE_SW" = "$WANT" ]; then
    echo "OK: the origin serves $WANT"
  else
    echo "STALE: uploaded $WANT but the origin serves app=$LIVE_APP sw=$LIVE_SW"
    RC=1
  fi
fi
exit $RC
