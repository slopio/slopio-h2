#!/usr/bin/env bash
# popple-h2 vs tokio+h2, swept over connection count.
#
# Both servers answer the same bytes (`200`, `read 0 bytes\n`, no headers of
# their own), get the same cores, and are driven by the same h2load on the
# cores they do not have. What is left between them is the server.
#
#     ./bench/run.sh                  # 100 1000 5000 10000 connections
#     CONNS="1000 20000" ./bench/run.sh
#
# SERVER_CORES/LOAD_CORES are taskset lists. The server gets the smaller half
# on purpose: a benchmark where h2load is the bottleneck measures h2load.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SERVER_CORES="${SERVER_CORES:-0,1}"
LOAD_CORES="${LOAD_CORES:-2-9}"
LOAD_THREADS="${LOAD_THREADS:-8}"
CONNS="${CONNS:-100 1000 5000 10000}"
STREAMS="${STREAMS:-1}"        # concurrent streams per connection
DURATION="${DURATION:-10}"
WARMUP="${WARMUP:-3}"
RING="${RING:-64x512}"
PORT_POPPLE=8080
PORT_TOKIO=8081

# One worker per server core, on both sides.
NCORES=$(taskset -c "$SERVER_CORES" nproc)

POPPLE_BIN="$ROOT/target/release/examples/bench_server"
TOKIO_BIN="$ROOT/bench/tokio-h2/target/release/tokio-h2-bench"
OUT="${OUT:-$ROOT/bench/results}"
mkdir -p "$OUT"

for bin in "$POPPLE_BIN" "$TOKIO_BIN"; do
  [ -x "$bin" ] || { echo "missing $bin — see bench/README.md" >&2; exit 1; }
done

start_popple() {
  PORT=$PORT_POPPLE RING=$RING PER_CORE=1 \
    taskset -c "$SERVER_CORES" "$POPPLE_BIN" >"$OUT/popple.log" 2>&1 &
  echo $!
}

start_tokio() {
  PORT=$PORT_TOKIO THREADS=$NCORES \
    taskset -c "$SERVER_CORES" "$TOKIO_BIN" >"$OUT/tokio.log" 2>&1 &
  echo $!
}

rss_kb() { awk '/^VmRSS:/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }

# Total CPU seconds the process has burned, ticks -> seconds. utime+stime over
# every thread, which is what /proc/PID/stat already sums.
cpu_sec() {
  awk -v hz="$(getconf CLK_TCK)" \
      '{ n=split($0, f, ") "); split(f[n], g, " "); print (g[12]+g[13])/hz }' \
      "/proc/$1/stat" 2>/dev/null || echo 0
}

# One (server, connection-count) cell. Prints a TSV row.
measure() {
  local name="$1" pid="$2" port="$3" conns="$4"
  local log="$OUT/$name-c$conns.txt"

  local cpu_before
  cpu_before=$(cpu_sec "$pid")

  # RSS after the run is RSS after the connections have gone. Poll while the
  # load is on and keep the peak, which is the number that answers "what does
  # a connection cost".
  local rssfile="$OUT/.rss.$$"
  # The peak is written out each round, not at the end: the poller is killed,
  # never allowed to finish, so anything it saves for later is lost.
  ( peak=0
    while kill -0 "$pid" 2>/dev/null; do
      cur=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
      if [ -n "${cur:-}" ] && [ "$cur" -gt "$peak" ]; then
        peak=$cur
        echo "$peak" >"$rssfile"
      fi
      sleep 0.2
    done ) &
  local poller=$!

  taskset -c "$LOAD_CORES" h2load \
    -t "$LOAD_THREADS" -c "$conns" -m "$STREAMS" \
    -D "$DURATION" --warm-up-time "$WARMUP" \
    "http://127.0.0.1:$port/" >"$log" 2>&1

  local cpu_after rss
  cpu_after=$(cpu_sec "$pid")
  kill "$poller" 2>/dev/null
  wait "$poller" 2>/dev/null
  rss=$(cat "$rssfile" 2>/dev/null || rss_kb "$pid")
  rm -f "$rssfile"

  if ! kill -0 "$pid" 2>/dev/null; then
    printf '%s\t%s\tSERVER DIED\n' "$name" "$conns"
    return 1
  fi

  # h2load's own summary. "finished in ..., N req/s"; the status line counts
  # 2xx/3xx/4xx/5xx; "failed" and "errored" are on the traffic summary.
  # h2load reports min/max/mean/sd for request time, not percentiles.
  local rps succ fail errd timeout mean max
  rps=$(awk '/req\/s/ && /finished in/ {for (i=1;i<=NF;i++) if ($i=="req/s,") print $(i-1)}' "$log" | head -1)
  succ=$(awk '/^status codes:/ {print $3}' "$log")
  fail=$(awk '/^requests:/ {for (i=1;i<=NF;i++) if ($i=="failed,") print $(i-1)}' "$log")
  errd=$(awk '/^requests:/ {for (i=1;i<=NF;i++) if ($i=="errored,") print $(i-1)}' "$log")
  timeout=$(awk '/^requests:/ {for (i=1;i<=NF;i++) if ($i=="timeout,") print $(i-1)}' "$log")
  read -r mean max < <(awk '/^time for request:/ {print $6, $5}' "$log")

  local cpu
  cpu=$(awk -v a="$cpu_after" -v b="$cpu_before" 'BEGIN{printf "%.2f", a-b}')

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$name" "$conns" "${rps:-?}" "${succ:-0}" "${fail:-0}" "${errd:-0}" \
    "${timeout:-0}" "$cpu" "$rss" "${mean:-?}" "${max:-?}"
}

echo "server cores: $SERVER_CORES ($NCORES) | load cores: $LOAD_CORES x$LOAD_THREADS threads"
echo "streams/conn: $STREAMS | duration: ${DURATION}s (+${WARMUP}s warm-up) | popple ring: $RING"
echo
printf 'server\tconns\treq/s\t2xx\tfailed\terrored\ttimeout\tcpu_s\trss_kb\tmean\tmax\n' | tee "$OUT/summary.tsv"

for server in popple tokio; do
  if [ "$server" = popple ]; then
    pid=$(start_popple); port=$PORT_POPPLE
  else
    pid=$(start_tokio); port=$PORT_TOKIO
  fi
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "$server failed to start; see $OUT/$server.log" >&2
    continue
  fi

  for c in $CONNS; do
    measure "$server" "$pid" "$port" "$c" | tee -a "$OUT/summary.tsv"
    # A run that killed the server invalidates the rest of its sweep.
    kill -0 "$pid" 2>/dev/null || break
  done

  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  sleep 1
done

echo
echo "raw h2load output in $OUT/"
