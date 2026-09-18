#!/usr/bin/env bash
# Where popple-h2 tops out, and what the read deadline costs there.
#
# Three sweeps, each against two binaries — the tree as it is, and the commit
# before the deadline landed — because the deadline arms and cancels a timer on
# every chunk, and a cost that is invisible at 300k req/s need not stay that way
# at the ceiling.
#
#     ./bench/heavy.sh            # all three sweeps
#     SWEEP=cores ./bench/heavy.sh
#
# `cpu/core` is the check that matters: below ~0.95 the server was not the
# bottleneck and the row measures h2load instead.
set -uo pipefail

ROOT=/home/cedric/popple-h2
AFTER="$ROOT/target/release/examples/bench_server"
BEFORE="/tmp/popple-before/target/release/examples/bench_server"
OUT="${OUT:-$ROOT/bench/results-heavy}"
DURATION="${DURATION:-10}"
WARMUP="${WARMUP:-3}"
SWEEP="${SWEEP:-all}"
RING="${RING:-64x512}"
mkdir -p "$OUT"

for bin in "$AFTER" "$BEFORE"; do
  [ -x "$bin" ] || { echo "missing $bin" >&2; exit 1; }
done

cpu_sec() {
  awk -v hz="$(getconf CLK_TCK)" \
      '{ n=split($0, f, ") "); split(f[n], g, " "); print (g[12]+g[13])/hz }' \
      "/proc/$1/stat" 2>/dev/null || echo 0
}

# one <label> <binary> <server-cores> <load-cores> <load-threads> <conns> <streams>
one() {
  local label="$1" bin="$2" scores="$3" lcores="$4" lthreads="$5" conns="$6" streams="$7"
  local ncores; ncores=$(taskset -c "$scores" nproc)
  local log="$OUT/${label}-c${conns}-m${streams}-n${ncores}.txt"

  PORT=8080 RING=$RING PER_CORE=1 taskset -c "$scores" "$bin" >"$OUT/server.log" 2>&1 &
  local pid=$!
  sleep 1
  kill -0 "$pid" 2>/dev/null || { echo "$label: server died"; cat "$OUT/server.log"; return 1; }

  local rssfile="$OUT/.rss.$$"
  ( peak=0
    while kill -0 "$pid" 2>/dev/null; do
      cur=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status" 2>/dev/null)
      if [ -n "${cur:-}" ] && [ "$cur" -gt "$peak" ]; then peak=$cur; echo "$peak" >"$rssfile"; fi
      sleep 0.2
    done ) &
  local poller=$!

  local before after
  before=$(cpu_sec "$pid")
  taskset -c "$lcores" h2load -t "$lthreads" -c "$conns" -m "$streams" \
    -D "$DURATION" --warm-up-time "$WARMUP" "http://127.0.0.1:8080/" >"$log" 2>&1
  after=$(cpu_sec "$pid")
  kill "$poller" 2>/dev/null; wait "$poller" 2>/dev/null
  local rss; rss=$(cat "$rssfile" 2>/dev/null || echo 0); rm -f "$rssfile"

  local rps fail errd timeout mean
  rps=$(awk '/req\/s/&&/finished in/{for(i=1;i<=NF;i++)if($i=="req/s,")print $(i-1)}' "$log" | head -1)
  fail=$(awk '/^requests:/{for(i=1;i<=NF;i++)if($i=="failed,")print $(i-1)}' "$log")
  errd=$(awk '/^requests:/{for(i=1;i<=NF;i++)if($i=="errored,")print $(i-1)}' "$log")
  timeout=$(awk '/^requests:/{for(i=1;i<=NF;i++)if($i=="timeout,")print $(i-1)}' "$log")
  mean=$(awk '/^time for request:/{print $6}' "$log")

  # Wall clock is warm-up plus duration; per-core CPU near 1.0 means saturated.
  local percore rpspc
  percore=$(awk -v a="$after" -v b="$before" -v n="$ncores" -v w="$((DURATION + WARMUP))" \
    'BEGIN{printf "%.2f", (a-b)/n/w}')
  rpspc=$(awk -v r="${rps:-0}" -v n="$ncores" 'BEGIN{printf "%.0f", r/n}')

  printf '%-8s %5s %6s %7s %12s %10s %7s %8s %9s %s\n' \
    "$label" "$ncores" "$conns" "$streams" "${rps:-?}" "$rpspc" "$percore" \
    "$rss" "${mean:-?}" "$(( ${fail:-0} + ${errd:-0} + ${timeout:-0} ))"

  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; sleep 1
}

header() {
  printf '\n%-8s %5s %6s %7s %12s %10s %7s %8s %9s %s\n' \
    build cores conns streams req/s req/s/core cpu/core rss_kb mean bad
}

if [ "$SWEEP" = all ] || [ "$SWEEP" = cores ]; then
  echo "=== core scaling (1000 connections, 1 stream each) ==="
  header
  for spec in "0:1-9:9" "0,1:2-9:8" "0-3:4-9:6"; do
    IFS=: read -r sc lc lt <<<"$spec"
    one after  "$AFTER"  "$sc" "$lc" "$lt" 1000 1
    one before "$BEFORE" "$sc" "$lc" "$lt" 1000 1
  done
fi

if [ "$SWEEP" = all ] || [ "$SWEEP" = streams ]; then
  echo
  echo "=== stream concurrency (2 cores, 500 connections) ==="
  header
  for m in 1 8 64; do
    one after  "$AFTER"  0,1 2-9 8 500 "$m"
    one before "$BEFORE" 0,1 2-9 8 500 "$m"
  done
fi

if [ "$SWEEP" = all ] || [ "$SWEEP" = conns ]; then
  echo
  echo "=== connection ceiling (2 cores, 1 stream each) ==="
  echo "    ~28k ephemeral ports on loopback, so 20k is the roof here."
  header
  for c in 10000 20000; do
    one after  "$AFTER"  0,1 2-9 8 "$c" 1
    one before "$BEFORE" 0,1 2-9 8 "$c" 1
  done
fi

echo
echo "raw h2load output in $OUT/"
