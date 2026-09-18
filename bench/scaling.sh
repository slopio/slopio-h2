#!/usr/bin/env bash
# How the two scale with cores, at matched accept capacity.
#
# One worker per server core on both sides, and one `SO_REUSEPORT` listener per
# worker on both sides — the tokio default is `LISTENERS=threads` for exactly
# this reason. h2load gets every core the server does not.
#
#     ./bench/scaling.sh
#     CONNS=5000 ./bench/scaling.sh
#
# `cpu/core` near 1.00 is the check that the row measures the server. Below
# ~0.95 the load generator ran out of cores and the row means nothing.
set -uo pipefail

ROOT=/home/cedric/popple-h2
POPPLE="$ROOT/target/release/examples/bench_server"
TOKIO="$ROOT/bench/tokio-h2/target/release/tokio-h2-bench"
CONNS="${CONNS:-1000}"
STREAMS="${STREAMS:-1}"
DURATION="${DURATION:-10}"
WARMUP="${WARMUP:-3}"
RING="${RING:-16x4096}"
OUT="${OUT:-$ROOT/bench/results-scaling}"
mkdir -p "$OUT"

cpu_sec() {
  awk -v hz="$(getconf CLK_TCK)" \
      '{ n=split($0, f, ") "); split(f[n], g, " "); print (g[12]+g[13])/hz }' \
      "/proc/$1/stat" 2>/dev/null || echo 0
}

one() {
  local name="$1" scores="$2" lcores="$3" lthreads="$4"
  local ncores; ncores=$(taskset -c "$scores" nproc)
  local log="$OUT/$name-n$ncores.txt"

  if [ "$name" = popple ]; then
    PORT=8080 RING=$RING PER_CORE=1 taskset -c "$scores" "$POPPLE" >"$OUT/$name.log" 2>&1 &
  else
    PORT=8080 THREADS=$ncores LISTENERS=$ncores taskset -c "$scores" "$TOKIO" >"$OUT/$name.log" 2>&1 &
  fi
  local pid=$!
  sleep 1
  kill -0 "$pid" 2>/dev/null || { echo "$name: failed to start"; return 1; }

  # Baseline before any connection: for popple this is mostly the buffer ring,
  # a per-worker fixed cost that scales with cores and not with connections.
  local base; base=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status")
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
  taskset -c "$lcores" h2load -t "$lthreads" -c "$CONNS" -m "$STREAMS" \
    -D "$DURATION" --warm-up-time "$WARMUP" "http://127.0.0.1:8080/" >"$log" 2>&1
  after=$(cpu_sec "$pid")
  kill "$poller" 2>/dev/null; wait "$poller" 2>/dev/null
  local peak; peak=$(cat "$rssfile" 2>/dev/null || echo 0); rm -f "$rssfile"

  if ! kill -0 "$pid" 2>/dev/null; then
    printf '%-8s %5s  SERVER DIED\n' "$name" "$ncores"
    return 1
  fi

  local rps mean max bad
  rps=$(awk '/req\/s/&&/finished in/{for(i=1;i<=NF;i++)if($i=="req/s,")print $(i-1)}' "$log" | head -1)
  read -r max mean < <(awk '/^time for request:/{print $5, $6}' "$log")
  bad=$(awk '/^requests:/{f=0;e=0;t=0;for(i=1;i<=NF;i++){if($i=="failed,")f=$(i-1);if($i=="errored,")e=$(i-1);if($i=="timeout,")t=$(i-1)}print f+e+t}' "$log")

  printf '%-8s %5s %12s %11.0f %8.2f %9s %9s %9s %s\n' \
    "$name" "$ncores" "${rps:-?}" \
    "$(awk -v r="${rps:-0}" -v n="$ncores" 'BEGIN{print r/n}')" \
    "$(awk -v a="$after" -v b="$before" -v n="$ncores" -v w="$((DURATION + WARMUP))" 'BEGIN{print (a-b)/n/w}')" \
    "$base" "$peak" \
    "${mean:-?}" "${bad:-0}"

  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; sleep 1
}

echo "connections: $CONNS | streams/conn: $STREAMS | ${DURATION}s (+${WARMUP}s warm-up) | popple ring: $RING"
# No per-connection column: at a fixed connection count the growth across core
# counts is popple's buffer ring being faulted in, one per worker, which
# dividing by connections would report as a per-connection cost it is not.
# Sweep connections at fixed cores for that number — `bench/run.sh` does.
printf '\n%-8s %5s %12s %11s %8s %9s %9s %9s %s\n' \
  server cores req/s req/s/core cpu/core base_kb peak_kb mean bad

# 10 cores here: the server takes the low ones, h2load gets the rest.
for spec in "0:1-9:9" "0,1:2-9:8" "0-3:4-9:6"; do
  IFS=: read -r sc lc lt <<<"$spec"
  one popple "$sc" "$lc" "$lt"
  one tokio  "$sc" "$lc" "$lt"
  echo
done

echo "raw h2load output in $OUT/"
