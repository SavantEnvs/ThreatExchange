#!/usr/bin/env bash
#
# mayhem/test.sh — RUN ThreatExchange's own C++ regression tests (built by mayhem/build.sh):
#  1. pdq's golden-output regression suite, pdq/cpp/reg_test/run, unmodified: photo hashes of the
#     bridge images (incl. dihedral variants), hashtool256, bit ops, MIH and clusterization,
#     diffed against pdq/cpp/reg_test/expected/out.
#  2. pdq's self-checking unit tests test-bits, test-hamming, test-flat (pdq/cpp/Makefile TESTS).
#  3. vpdq's regression check (vpdq/cpp/regtest.py): all 16 sample videos x {1, auto} threads,
#     each matched line-by-line against vpdq/sample-hashes, plus the frame-order check.
#  4. tmk's regression check (tmk/cpp/Makefile regtest): 15 sample videos hashed and compared
#     against tmk/sample-hashes.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
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

T="$SRC/mayhem/build/test"
for b in hashtool256 pdq-photo-hasher test-bits test-hamming test-flat test-mih clusterize256 clusterize256x \
         vpdq-hash-video match-hashes-byline tmk-hash-video tmk-compare-two-tmks; do
  [ -x "$T/$b" ] || { echo "test.sh: $T/$b missing — run mayhem/build.sh first" >&2; emit_ctrf "pdq+vpdq+tmk-regtest" 0 1; exit 1; }
done
passed=0 failed=0
W="$(mktemp -d "${TMPDIR:-/tmp}/te-test.XXXXXX")"
trap 'rm -rf "$W"' EXIT

# 1) pdq regression suite. reg_test/run expects to be run as ./reg_test/run from pdq/cpp with the
#    tools in the cwd, reading ../data and writing ./output-regtest; mirror that layout in a scratch
#    dir so the tracked pdq/cpp/output-regtest is not rewritten.
mkdir -p "$W/pdq/cpp"
ln -s "$SRC/pdq/data" "$W/pdq/data"
ln -s "$SRC/pdq/cpp/reg_test" "$W/pdq/cpp/reg_test"
for b in hashtool256 pdq-photo-hasher test-bits test-mih clusterize256 clusterize256x; do
  ln -s "$T/$b" "$W/pdq/cpp/$b"
done
log="$W/pdq-regtest.log"
if (cd "$W/pdq/cpp" && ./reg_test/run) >"$log" 2>&1 && grep -q "ALL REGRESSION TESTS PASSED" "$log"; then
  n=$(sed -n 's/^Tests completed: //p' "$log" | tail -1)
  echo "pdq regtest: PASS ($n commands)"
  passed=$(( passed + ${n:-1} ))
else
  tail -40 "$log"
  echo "pdq regtest: FAIL"
  failed=$(( failed + 1 ))
fi

# 2) pdq's self-checking unit tests (pdq/cpp/Makefile TESTS: run-test-bits run-test-hamming
#    run-test-flat), run with no arguments as the Makefile does; each exits non-zero on a mismatch.
for b in test-bits test-hamming test-flat; do
  log="$W/$b.log"
  if (cd "$W/pdq/cpp" && "$T/$b") >"$log" 2>&1; then
    echo "pdq $b: PASS"; passed=$(( passed + 1 ))
  else
    tail -20 "$log"; echo "pdq $b: FAIL"; failed=$(( failed + 1 ))
  fi
done

# 3) vpdq's regression check (vpdq/cpp/regtest.py): hash every tmk/sample-videos/*.mp4 at every
#    frame (-r 0 -s 0) with one thread and with auto threads; compare each against its golden
#    vpdq/sample-hashes/<stem>.txt with match-hashes-byline (golden first, tolerances 31/50),
#    requiring 100.000% of compared lines to match, and require consecutive frame numbers 0,1,2,...
frame_order_ok() {
  awk -F, 'BEGIN{n=0} {if ($1 != n) exit 1; n++} END{if (n == 0) exit 1}' "$1"
}
for th in 1 0; do
  for v in tmk/sample-videos/*.mp4; do
    stem="$(basename "$v" .mp4)"
    out="$W/vpdq-$stem-$th.txt"
    res=""
    if "$T/vpdq-hash-video" -r 0 -s 0 -t "$th" -i "$v" -o "$out" >"$W/vpdq.log" 2>&1 \
       && res=$("$T/match-hashes-byline" "vpdq/sample-hashes/$stem.txt" "$out" 31 50 2>&1) \
       && echo "$res" | grep -qx "100.000 Percentage matches" \
       && frame_order_ok "$out"; then
      echo "vpdq $stem (threads=$th): PASS"; passed=$(( passed + 1 ))
    else
      tail -5 "$W/vpdq.log"; echo "$res"
      echo "vpdq $stem (threads=$th): FAIL"; failed=$(( failed + 1 ))
    fi
  done
done

# 4) tmk's regression check (tmk/cpp/Makefile `regtest`, the default goal upstream CI runs): hash
#    each of the 15 sample videos with tmk-hash-video (frames from the ffmpeg CLI) and compare the
#    .tmk against tmk/sample-hashes with tmk-compare-two-tmks (tol 0.08; exits 1 on a mismatch).
mkdir -p "$W/tmk"
for g in tmk/sample-hashes/*.tmk; do
  stem="$(basename "$g" .tmk)"
  log="$W/tmk-$stem.log"
  if "$T/tmk-hash-video" -f /usr/bin/ffmpeg -d "$W/tmk" -i "tmk/sample-videos/$stem.mp4" >"$log" 2>&1 \
     && "$T/tmk-compare-two-tmks" "$W/tmk/$stem.tmk" "$g" >>"$log" 2>&1; then
    echo "tmk $stem: PASS"; passed=$(( passed + 1 ))
  else
    tail -10 "$log"; echo "tmk $stem: FAIL"; failed=$(( failed + 1 ))
  fi
done

emit_ctrf "pdq+vpdq+tmk-regtest" "$passed" "$failed"
