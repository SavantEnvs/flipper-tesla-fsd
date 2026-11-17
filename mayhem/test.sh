#!/usr/bin/env bash
#
# mayhem/test.sh — run upstream's host unit tests (test/Makefile), built by mayhem/build.sh with
# the project's normal flags. Every suite counts its own CHECK()s; a suite passes only when it
# exits 0 AND prints its own success line with a non-zero pass count and 0 failures (or, for the
# suites that abort on the first failed assert, their "... tests passed" line). A no-op binary
# prints nothing, so it fails here.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
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

# suite → how it reports success: "count" = "<N> passed, <F> failed"; otherwise the exact
# success line it prints.
declare -A EXPECT=(
  [test_fsd_core]=count
  [test_esp32_core]=count
  [test_captive_probe]=count
  [test_web_cmd]=count
  [test_web_origin]=count
  [test_page_send]=count
  [test_can_capture_filter]="CAN capture tests passed"
  [test_can_mcp2518fd]="MCP2518FD tests passed"
  [test_can_counters]="CAN counter tests passed"
  [test_loop_health]="Loop health tests passed"
  [test_power_log]="Power log tests passed"
  [test_rx_whitelist]=count
)

passed=0 failed=0
for t in test_fsd_core test_esp32_core test_can_capture_filter test_captive_probe test_can_mcp2518fd \
         test_web_cmd test_web_origin test_can_counters test_loop_health test_power_log \
         test_page_send test_rx_whitelist; do
  bin="test/$t"
  if [ ! -x "$bin" ]; then
    echo "FAIL $t: $bin missing — mayhem/build.sh should have built it" >&2
    failed=$((failed + 1)); continue
  fi
  out="$(cd test && "./$t" 2>&1)"; rc=$?
  ok=0
  if [ $rc -eq 0 ]; then
    if [ "${EXPECT[$t]}" = count ]; then
      line="$(printf '%s\n' "$out" | grep -E '^([a-z_0-9]+: )?[0-9]+ passed, [0-9]+ failed$' | tail -1)"
      p="$(printf '%s' "$line" | sed -E 's/^([a-z_0-9]+: )?([0-9]+) passed.*/\2/')"
      f="$(printf '%s' "$line" | sed -E 's/.* ([0-9]+) failed$/\1/')"
      [ -n "$line" ] && [ "$p" -gt 0 ] && [ "$f" -eq 0 ] && ok=1
    else
      printf '%s\n' "$out" | grep -qF "${EXPECT[$t]}" && ok=1
    fi
  fi
  if [ $ok -eq 1 ]; then
    echo "PASS $t ${line:-}"; passed=$((passed + 1))
  else
    echo "FAIL $t (exit $rc)"; printf '%s\n' "$out" | tail -20; failed=$((failed + 1))
  fi
  line=""
done

emit_ctrf "host-unit-tests" "$passed" "$failed"
