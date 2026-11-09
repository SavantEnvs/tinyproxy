#!/usr/bin/env bash
#
# mayhem/build.sh — build tinyproxy's fuzz harnesses and its test binary.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem, offline and re-runnable.
#   mayhem/build-fuzz   out-of-tree build of the project with $SANITIZER_FLAGS + coverage (gitignored)
#   mayhem/build-test   out-of-tree build with the project's normal flags, run by mayhem/test.sh (gitignored)
#   /mayhem/fuzz_*              libFuzzer binaries
#   /mayhem/fuzz_*-standalone   run-once reproducers (input file as argv[1])
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

HARNESSES="fuzz_conf fuzz_request fuzz_response fuzz_hostspec fuzz_template"

# configure and Makefile.in are generated and gitignored upstream, so they are recreated here.
autoreconf -fi

# 1) The project with sanitizers, DWARF 3 and SanCov. Out of tree because upstream does not ignore *.o.
FB="$SRC/mayhem/build-fuzz"
mkdir -p "$FB"
cd "$FB"
# configure's own test programs run under ASan; only they need LeakSanitizer off to link and run cleanly.
ASAN_OPTIONS=detect_leaks=0 "$SRC/configure" CC="$CC" \
  CFLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
  LDFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link"
make -C "$FB/src" -j"$MAYHEM_JOBS" tinyproxy

# main.o defines main(), and the harnesses include reqs.c / conf.c themselves, so those
# translation units come from the harness and the rest of the project from this archive.
rm -f "$FB/libtinyproxy.a"
ar rcs "$FB/libtinyproxy.a" $(ls "$FB"/src/*.o | grep -v '/main\.o$')

# 2) Harnesses: fuzzer binary + standalone reproducer, both linked against the sanitized project.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FB/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FB/standalone_main.o"
INCS="-DHAVE_CONFIG_H -DNDEBUG -I$SRC/mayhem -I$SRC/src -I$FB -I$FB/src"
for h in $HARNESSES; do
  $CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $INCS $LIB_FUZZING_ENGINE \
      "$SRC/mayhem/$h.c" "$FB/lsan_off.o" "$FB/libtinyproxy.a" -lpthread -o "$SRC/$h"
  $CC -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $INCS \
      "$SRC/mayhem/$h.c" "$FB/standalone_main.o" "$FB/lsan_off.o" "$FB/libtinyproxy.a" -lpthread \
      -o "$SRC/$h-standalone"
done

# 3) The tinyproxy binary exercised by mayhem/test.sh: normal flags, no sanitizers.
TB="$SRC/mayhem/build-test"
mkdir -p "$TB"
cd "$TB"
env -u CFLAGS -u LDFLAGS "$SRC/configure" CC="$CC" CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
make -C "$TB/src" -j"$MAYHEM_JOBS" tinyproxy
