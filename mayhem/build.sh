#!/usr/bin/env bash
#
# mayhem/build.sh — build the flipper-tesla-fsd fuzz harnesses and the upstream host tests.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. Neither upstream
# firmware build (ufbt for the Flipper app, PlatformIO for the ESP32) can run on a host; upstream
# keeps the protocol logic host-compilable instead and builds it with plain cc/c++ in
# test/Makefile. The harnesses compile the same sources the same way, with the sanitizers on.
# Outputs: mayhem/out/<target> and mayhem/out/<target>-standalone (gitignored by mayhem/.gitignore);
# the host tests land in test/ (gitignored upstream), where mayhem/test.sh runs them.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:?STANDALONE_FUZZ_MAIN must point at the base image run-once driver}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
OBJ="$OUT/obj"
H="$SRC/mayhem/harnesses"
mkdir -p "$OUT" "$OBJ"

FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"
CFL="-std=c11 $FLAGS"
CXXFL="-std=c++17 $FLAGS"
# Same include order as test/Makefile: esp32/.firmware first so "fsd_handler.h" is the firmware
# header there, fsd_logic/fsd_handler.h on the Flipper side.
ESP_INC="-I$SRC/esp32/.firmware -I$SRC/fsd_logic -I$H"
FLIP_INC="-I$SRC/fsd_logic -I$H"

# Generated sources (mayhem/out/gen/). The handlers keep protocol state in file- and function-scope
# statics that fsd_state_init() cannot reach (nag PRNG and torque walk, Mode-C tracker, gear-lever
# tracker). Each input must start from the same state, so the harnesses compile a copy of the handler
# in which every "static T name = init;" is registered with a resettable block
# (mayhem/harnesses/fsd_resettable.h) that fsd_rs_reset_all() restores. The rewrite is one line for
# one line, and "#line" keeps backtraces on upstream's file and line numbers. Upstream's files are
# not modified, and test/ keeps building the originals.
GEN="$OUT/gen"
mkdir -p "$GEN"
make_resettable() {  # <upstream source> <generated copy>
  { printf '#line 1 "%s"\n' "$1"
    sed -E \
      -e 's/^static[[:space:]]+(uint8_t|uint16_t|uint32_t|int16_t|bool)[[:space:]]+([A-Za-z_0-9]+)[[:space:]]*=[[:space:]]*([^;]+);/FSD_RS_G(\1, \2, \3);/' \
      -e 's/^([[:space:]]+)static[[:space:]]+(uint8_t|uint16_t|uint32_t|int16_t|bool)[[:space:]]+([A-Za-z_0-9]+)[[:space:]]*=[[:space:]]*([^;]+);/\1FSD_RS_L(\2, \3, \4);/' \
      "$1"
  } > "$2"
  echo "make_resettable: $1: $(grep -cE 'FSD_RS_[GL]\(' "$2") statics gathered"
  # Anything still static, writable and not a function would carry state between inputs.
  if grep -nE '^[[:space:]]*static[[:space:]]+[^(]*(=|;)' "$2" | grep -vE 'static[[:space:]]+(const|constexpr)\b'; then
    echo "WARNING: $1 has statics that are not reset between inputs (listed above)" >&2
  fi
}
make_resettable esp32/.firmware/fsd_handler.cpp "$GEN/esp32_fsd_handler.cpp"
make_resettable fsd_logic/fsd_handler.c "$GEN/flipper_fsd_handler.c"

# The :82 stream's query-string filter parser lives among static functions of an Arduino/FreeRTOS
# translation unit (http_can_stream.cpp). Cut those functions out of upstream's file as they are,
# together with the globals and the limit they use, so the harness runs upstream's own code.
awk -v F="esp32/.firmware/http_can_stream.cpp" '
  /^#define HTTP_CAN_STREAM_MAX_FILTER_IDS/ || /^static .* g_(filter_ids|filter_count|bus_filter_enabled|bus_filter|meta_enabled)[ \[;=]/ {
    printf "#line %d \"%s\"\n%s\n", NR, F, $0; ndecl++ }
  /^static void id_filter_reset\(\)/ { on = 1; printf "#line %d \"%s\"\n", NR, F }
  /^static void close_stream\(\)/ { on = 0 }
  on { print; nbody++ }
  END { if (ndecl != 6 || nbody < 100) { print "stream filter extraction failed: upstream changed" > "/dev/stderr"; exit 3 } }
' esp32/.firmware/http_can_stream.cpp > "$GEN/http_can_stream_filter.inc"

# Sanitized project objects, built twice: with SanitizerCoverage for the libFuzzer binary, and
# without it for the -standalone reproducer (which has no libFuzzer runtime to provide the hooks).
COV="${LIB_FUZZING_ENGINE/-fsanitize=fuzzer/-fsanitize=fuzzer-no-link}"
RS_INC="-include $H/fsd_resettable.h"
$CC $FLAGS -c mayhem/lsan_off.c -o "$OBJ/lsan_off.o"
$CC $FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
for kind in fuzz sa; do
  extra=""; [ "$kind" = fuzz ] && extra="$COV"
  mkdir -p "$OBJ/$kind"
  $CC $CFL $extra -c "$H/fsd_resettable.c" -o "$OBJ/$kind/fsd_resettable.o"
  $CXX $CXXFL $extra $RS_INC $ESP_INC -c "$GEN/esp32_fsd_handler.cpp" -o "$OBJ/$kind/esp32_fsd_handler.o"
  $CC $CFL $extra $RS_INC $FLIP_INC -c "$GEN/flipper_fsd_handler.c" -o "$OBJ/$kind/flipper_fsd_handler.o"
  for f in fsd_profile fsd_power; do
    $CC $CFL $extra $FLIP_INC -c "fsd_logic/$f.c" -o "$OBJ/$kind/flipper_$f.o"
  done
done

# link <target> <lang c|cxx> <harness> <includes> <project objects, relative to obj/<kind>/...>
link() {
  local t="$1" lang="$2" src="$3" inc="$4"; shift 4
  local comp="$CC $CFL" o fobjs=() sobjs=()
  [ "$lang" = cxx ] && comp="$CXX $CXXFL"
  for o in "$@"; do fobjs+=("$OBJ/fuzz/$o"); sobjs+=("$OBJ/sa/$o"); done
  $comp $COV $inc -c "$src" -o "$OBJ/fuzz/$t.o"
  $comp $inc -c "$src" -o "$OBJ/sa/$t.o"
  $CXX $FLAGS $LIB_FUZZING_ENGINE "$OBJ/fuzz/$t.o" "${fobjs[@]}" "$OBJ/lsan_off.o" -lm -o "$OUT/$t"
  $CXX $FLAGS "$OBJ/standalone_main.o" "$OBJ/sa/$t.o" "${sobjs[@]}" "$OBJ/lsan_off.o" -lm -o "$OUT/$t-standalone"
}

FLIP_OBJS="flipper_fsd_handler.o flipper_fsd_profile.o flipper_fsd_power.o fsd_resettable.o"
link esp32_can_rx     cxx "$H/fuzz_esp32_can_rx.cpp"    "$ESP_INC"  esp32_fsd_handler.o fsd_resettable.o
link flipper_can_rx   c   "$H/fuzz_flipper_can_rx.c"    "$FLIP_INC" $FLIP_OBJS
link cantest_profile  c   "$H/fuzz_cantest_profile.c"   "$FLIP_INC" $FLIP_OBJS
link web_cmd          cxx "$H/fuzz_web_cmd.cpp"         "-I$SRC/esp32/.firmware"
link web_origin       cxx "$H/fuzz_web_origin.cpp"      "-I$SRC/esp32/.firmware"
link captive_probe    cxx "$H/fuzz_captive_probe.cpp"   "-I$SRC/esp32/.firmware"
link stream_filter    cxx "$H/fuzz_stream_filter.cpp"   "-I$SRC/esp32/.firmware -I$SRC/fsd_logic -I$GEN"

# Upstream host tests (test/Makefile), with the project's normal flags — no sanitizers.
# test_web_page.py is left out: it compiles C++ itself when run, and test.sh must not build.
make -C test -j"$MAYHEM_JOBS" CC="$CC" CXX="$CXX" \
  CFLAGS="-std=c11 -Wall -Wextra -O0 -g $COVERAGE_FLAGS" \
  CXXFLAGS="-std=c++17 -Wall -Wextra -O0 -g $COVERAGE_FLAGS" \
  test_fsd_core test_esp32_core test_can_capture_filter test_captive_probe test_can_mcp2518fd \
  test_web_cmd test_web_origin test_can_counters test_loop_health test_power_log test_page_send \
  test_rx_whitelist
