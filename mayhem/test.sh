#!/usr/bin/env bash
#
# mayhem/test.sh — runs tinyproxy (built by mayhem/build.sh with its normal flags) as a real proxy on
# loopback and checks what it does with hand-written requests: the status line, headers and body for
# plain GETs, POSTs, CONNECT tunnels, filters, ACLs, basic auth, reverse paths and error pages.
# Upstream's own tests (perl, tests/scripts) need HTTP::Daemon, which is not in the image.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/mayhem/build-test/src/tinyproxy"
if [ ! -x "$BIN" ]; then
  echo "missing $BIN: mayhem/build.sh should have built it" >&2
  emit_ctrf "tinyproxy-http" 0 1 0
  exit 1
fi

out="$(timeout 300 python3 "$SRC/mayhem/proxy_tests.py" "$BIN" 2>&1)"
echo "$out"
res="$(printf '%s\n' "$out" | sed -n 's/^RESULT \([0-9]*\) \([0-9]*\)$/\1 \2/p' | tail -1)"
if [ -z "$res" ]; then
  emit_ctrf "tinyproxy-http" 0 1 0
  exit 1
fi
set -- $res
emit_ctrf "tinyproxy-http" "$1" "$2" 0
