#!/usr/bin/env bash
#
# mayhem/build.sh — build ThreatExchange's C++ hashing libraries (pdq, tmk, vpdq)
# with sanitizers, the fuzz harnesses in mayhem/harnesses/, their -standalone
# reproducers, and (with normal flags) the upstream test tools mayhem/test.sh runs.
#
# Upstream builds pdq/tmk with plain Makefiles (whose default goal also runs
# regression tests) and vpdq with CMake + pkg-config (with -Werror). The sources
# are compiled here directly with the same include roots: the repo root for
# pdq/tmk (<pdq/cpp/...>, <tmk/cpp/...>) and vpdq/cpp for vpdq, which carries its
# own copy of pdq (never mix the two copies in one binary). libav* come from the
# apt -dev packages installed in mayhem/Dockerfile.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"          # gitignored by mayhem/.gitignore
rm -rf "$B"
mkdir -p "$B/fuzz" "$B/test"

PDQ_SRCS="pdq/cpp/common/pdqhashtypes.cpp pdq/cpp/io/hashio.cpp pdq/cpp/common/pdqhamming.cpp
 pdq/cpp/hashing/pdqhashing.cpp pdq/cpp/downscaling/downscaling.cpp pdq/cpp/io/pdqio.cpp
 pdq/cpp/hashing/torben.cpp pdq/cpp/common/pdqutils.cpp"
TMK_SRCS="tmk/cpp/algo/tmkfv.cpp tmk/cpp/io/tmkio.cpp tmk/cpp/lib/vec.cpp
 tmk/cpp/hashing/bufferhashers.cpp"
VPDQ_SRCS="vpdq/cpp/vpdq/cpp/hashing/bufferhasher.cpp vpdq/cpp/vpdq/cpp/hashing/bufferhasherfactory.cpp
 vpdq/cpp/vpdq/cpp/hashing/ffmpegwrapper.cpp vpdq/cpp/vpdq/cpp/hashing/filehasher.cpp
 vpdq/cpp/vpdq/cpp/hashing/matchTwoHash.cpp vpdq/cpp/vpdq/cpp/hashing/pdqbufferhasher.cpp
 vpdq/cpp/vpdq/cpp/io/vpdqio.cpp
 vpdq/cpp/pdq/cpp/common/pdqhashtypes.cpp vpdq/cpp/pdq/cpp/common/pdqhamming.cpp
 vpdq/cpp/pdq/cpp/hashing/pdqhashing.cpp vpdq/cpp/pdq/cpp/hashing/torben.cpp
 vpdq/cpp/pdq/cpp/downscaling/downscaling.cpp"
LIBAV_CFLAGS="$(pkg-config --cflags libavformat libavcodec libswscale libavutil)"
LIBAV_LIBS="$(pkg-config --libs libavformat libavcodec libswscale libavutil)"

# lib <outdir> <name> <include-root> "<flags>" <srcs...>: compile and archive
lib() {
  local out="$1" name="$2" inc="$3" flags="$4"; shift 4
  local objs=() pids=() s o p
  mkdir -p "$out/$name"
  for s in "$@"; do
    o="$out/$name/$(echo "$s" | tr '/' '_').o"
    objs+=("$o")
    # shellcheck disable=SC2086
    $CXX -std=c++14 $flags -Dcimg_display=0 -I"$inc" -I"$inc/pdq/cpp" $LIBAV_CFLAGS -c "$s" -o "$o" &
    pids+=("$!")
    if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
  done
  for p in "${pids[@]}"; do wait "$p"; done
  ar rcs "$out/lib$name.a" "${objs[@]}"
}

# ---- 1) sanitized libraries + harnesses -------------------------------------
# -fsanitize=fuzzer-no-link: SanCov-instrument the project code too, so libFuzzer sees its edges
FZ="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1"
# shellcheck disable=SC2086
lib "$B/fuzz" pdq  "$SRC"          "$FZ" $PDQ_SRCS
# shellcheck disable=SC2086
lib "$B/fuzz" tmk  "$SRC"          "$FZ" $TMK_SRCS
# shellcheck disable=SC2086
lib "$B/fuzz" vpdq "$SRC/vpdq/cpp" "$FZ" $VPDQ_SRCS

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/fuzz/lsan_off.o"

# harness <name> <include-root> "<libs>"
harness() {
  local name="$1" inc="$2" libs="$3"
  # shellcheck disable=SC2086
  $CXX -std=c++14 $FZ -Dcimg_display=0 -I"$inc" -I"$inc/pdq/cpp" $LIBAV_CFLAGS -c "mayhem/harnesses/$name.cc" -o "$B/fuzz/$name.o"
  # shellcheck disable=SC2086
  $CXX $FZ $LIB_FUZZING_ENGINE "$B/fuzz/$name.o" "$B/fuzz/lsan_off.o" $libs -lm -lpthread -o "/mayhem/$name"
  # shellcheck disable=SC2086
  $CXX $FZ "$B/fuzz/standalone_main.o" "$B/fuzz/$name.o" "$B/fuzz/lsan_off.o" $libs -lm -lpthread -o "/mayhem/$name-standalone"
}
harness vpdq_hash_video   "$SRC/vpdq/cpp" "$B/fuzz/libvpdq.a $LIBAV_LIBS"
harness tmk_read_features "$SRC" "$B/fuzz/libtmk.a $B/fuzz/libpdq.a"
harness tmk_vstr_hash     "$SRC" "$B/fuzz/libtmk.a $B/fuzz/libpdq.a"
harness pdq_image_hash    "$SRC" "$B/fuzz/libpdq.a"
harness pdq_float_luma    "$SRC" "$B/fuzz/libpdq.a"
harness pdq_hash_mih      "$SRC" "$B/fuzz/libpdq.a"

# ---- 2) upstream test tools, normal flags (run by mayhem/test.sh) -----------
TF="-O2 $COVERAGE_FLAGS"
# shellcheck disable=SC2086
lib "$B/test" pdq  "$SRC"          "$TF" $PDQ_SRCS
# shellcheck disable=SC2086
lib "$B/test" vpdq "$SRC/vpdq/cpp" "$TF" $VPDQ_SRCS
for t in hashtool256 test-bits test-hamming test-flat test-mih clusterize256 clusterize256x; do
  $CXX -std=c++14 $TF -Dcimg_display=0 -I"$SRC" -I"$SRC/pdq/cpp" "pdq/cpp/bin/$t.cpp" "$B/test/libpdq.a" -lm -lpthread -o "$B/test/$t"
done
# pdq-photo-hasher decodes the regression JPEGs with libjpeg (cimg_use_jpeg)
# rather than CImg's ImageMagick fallback.
$CXX -std=c++14 $TF -Dcimg_display=0 -Dcimg_use_jpeg -I"$SRC" -I"$SRC/pdq/cpp" pdq/cpp/bin/pdq-photo-hasher.cpp \
  pdq/cpp/io/pdqio.cpp "$B/test/libpdq.a" -ljpeg -lm -lpthread -o "$B/test/pdq-photo-hasher"
for t in vpdq-hash-video match-hashes-brute match-hashes-byline; do
  # shellcheck disable=SC2086
  $CXX -std=c++14 $TF -I"$SRC/vpdq/cpp" $LIBAV_CFLAGS "vpdq/cpp/apps/$t.cpp" "$B/test/libvpdq.a" $LIBAV_LIBS -lm -lpthread -o "$B/test/$t"
done
# tmk regression tools (tmk/cpp/Makefile `regtest`): the full tmk library as upstream's LIBSRC,
# with the pdq sources it links; tmk-hash-video pipes frames from the ffmpeg CLI.
# shellcheck disable=SC2086
lib "$B/test" tmk "$SRC" "$TF" $TMK_SRCS tmk/cpp/hashing/filehasher.cpp \
  tmk/cpp/raster/rasterwriters.cpp tmk/cpp/raster/timeresamplers.cpp
for t in tmk-hash-video tmk-compare-two-tmks; do
  $CXX -std=c++14 $TF -I"$SRC" "tmk/cpp/bin/$t.cpp" "$B/test/libtmk.a" "$B/test/libpdq.a" -lm -lpthread -o "$B/test/$t"
done
echo "build.sh: done"
