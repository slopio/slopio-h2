#!/usr/bin/env bash
# popple-h2 vs libh2o: the same routes, the same bytes, the same cores.
#
#     cargo build --release --example bench_server --example idle_clients
#     bench/h2o/build.sh
#     bench/vs-h2o.sh
#
# Three questions, one table each:
#
#   payload   what a request costs, by what it carries — GET of 13 B to 64 KiB,
#             POST of 16 KiB and 1 MiB — at a fixed 100 connections x 10 streams
#   conns     what a connection costs under load: 1 stream each, swept in count
#   idle      what a connection costs before it has asked for anything
#
# Every cell is run ROUNDS times with the two servers alternating who goes
# first, and each server is restarted per cell: RSS is a peak, and a peak left
# over from the previous cell is not this cell's. The table reports the mean
# and the spread, because a difference smaller than the spread is not one.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SERVER_CORES="${SERVER_CORES:-0,1}"
LOAD_CORES="${LOAD_CORES:-2-9}"
LOAD_THREADS="${LOAD_THREADS:-8}"
DURATION="${DURATION:-8}"
WARMUP="${WARMUP:-2}"
ROUNDS="${ROUNDS:-2}"
RING="${RING:-64x128+512}"
CONNS="${CONNS:-100 1000 10000}"
IDLE_N="${IDLE_N:-10000}"
PORT_POPPLE=8080
PORT_H2O=8081

NCORES=$(taskset -c "$SERVER_CORES" nproc)
POPPLE_BIN="$ROOT/target/release/examples/bench_server"
IDLE_BIN="$ROOT/target/release/examples/idle_clients"
H2O_BIN="$ROOT/bench/h2o/server"
OUT="${OUT:-$ROOT/bench/results-h2o}"
mkdir -p "$OUT"

for bin in "$POPPLE_BIN" "$IDLE_BIN" "$H2O_BIN"; do
  [ -x "$bin" ] || { echo "missing $bin — see the head of this script" >&2; exit 1; }
done

head -c 16384 /dev/zero >"$OUT/up16k.bin"
head -c 1048576 /dev/zero >"$OUT/up1m.bin"

start() { # name -> pid
  case "$1" in
    popple) PORT=$PORT_POPPLE RING=$RING PER_CORE=1 \
              taskset -c "$SERVER_CORES" "$POPPLE_BIN" >"$OUT/popple.log" 2>&1 & ;;
    h2o)    PORT=$PORT_H2O THREADS=$NCORES \
              taskset -c "$SERVER_CORES" "$H2O_BIN" >"$OUT/h2o.log" 2>&1 & ;;
  esac
  echo $!
}
port_of() { [ "$1" = popple ] && echo $PORT_POPPLE || echo $PORT_H2O; }

rss_kb() { awk '/^VmRSS:/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
cpu_sec() {
  awk -v hz="$(getconf CLK_TCK)" \
      '{ n=split($0, f, ") "); split(f[n], g, " "); print (g[12]+g[13])/hz }' \
      "/proc/$1/stat" 2>/dev/null || echo 0
}

# One run of one cell against a fresh server. Prints: rps cpu_s peak_rss_kb
# mean_latency max_latency failed
run_cell() { # server conns streams h2load-args...
  local server="$1" conns="$2" streams="$3"; shift 3
  local pid port log="$OUT/.h2load.$$"
  pid=$(start "$server"); port=$(port_of "$server")
  sleep 0.8
  if ! kill -0 "$pid" 2>/dev/null; then echo "DIED 0 0 0 0 0"; return; fi

  local rssfile="$OUT/.rss.$$"; echo 0 >"$rssfile"
  ( peak=0
    while kill -0 "$pid" 2>/dev/null; do
      cur=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
      if [ -n "${cur:-}" ] && [ "$cur" -gt "$peak" ]; then peak=$cur; echo "$peak" >"$rssfile"; fi
      sleep 0.1
    done ) &
  local poller=$!

  local cpu_before; cpu_before=$(cpu_sec "$pid")
  # shellcheck disable=SC2068
  taskset -c "$LOAD_CORES" h2load -t "$LOAD_THREADS" -c "$conns" -m "$streams" \
    -D "$DURATION" --warm-up-time "$WARMUP" ${@//PORT/$port} >"$log" 2>&1
  local cpu_after; cpu_after=$(cpu_sec "$pid")

  local alive=1; kill -0 "$pid" 2>/dev/null || alive=0
  kill "$poller" 2>/dev/null; wait "$poller" 2>/dev/null
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null

  local rps fail mean max
  rps=$(awk '/req\/s/ && /finished in/ {for (i=1;i<=NF;i++) if ($i=="req/s,") print $(i-1)}' "$log" | head -1)
  fail=$(awk '/^requests:/ {for (i=1;i<=NF;i++) if ($i=="failed,") print $(i-1)}' "$log")
  read -r mean max < <(awk '/^time for request:/ {print $6, $5}' "$log")
  [ "$alive" = 1 ] || rps=DIED
  echo "${rps:-?} $(awk -v a="$cpu_after" -v b="$cpu_before" 'BEGIN{printf "%.2f", a-b}')" \
       "$(cat "$rssfile")" "${mean:-?}" "${max:-?}" "${fail:-0}"
  rm -f "$rssfile" "$log"
}

# A cell, ROUNDS times, alternating which server goes first.
cell() { # table label conns streams h2load-args...
  local table="$1" label="$2"; shift 2
  local order r server
  for r in $(seq 1 "$ROUNDS"); do
    order="popple h2o"; [ $((r % 2)) -eq 0 ] && order="h2o popple"
    for server in $order; do
      printf '%s\t%s\t%s\t%s\t%s\n' "$table" "$label" "$server" "$r" \
        "$(run_cell "$server" "$@" | tr ' ' '\t')" | tee -a "$OUT/raw.tsv"
    done
  done
}

# RSS of `N` connections that finished their handshake and asked for nothing,
# over the server's own baseline.
idle() { # server
  local server="$1" pid port base held
  pid=$(start "$server"); port=$(port_of "$server")
  sleep 0.8
  base=$(rss_kb "$pid")
  N=$IDLE_N ADDR=127.0.0.1:$port taskset -c "$LOAD_CORES" "$IDLE_BIN" >"$OUT/idle-$server.log" 2>&1 &
  local client=$!
  # Until the count of established connections on the port stops growing.
  local seen=0 now=0 stable=0
  while [ "$stable" -lt 5 ]; do
    sleep 0.5
    now=$(ss -Htn state established "( sport = :$port )" 2>/dev/null | wc -l)
    if [ "$now" -eq "$seen" ] && [ "$now" -gt 0 ]; then stable=$((stable + 1)); else stable=0; fi
    seen=$now
    kill -0 "$client" 2>/dev/null || break
  done
  held=$(rss_kb "$pid")
  printf 'idle\t%s\t%s\t%s\t%s\t%s\n' "$server" "$seen" "$base" "$held" \
    "$(awk -v h="$held" -v b="$base" -v n="$seen" 'BEGIN{ if (n>0) printf "%.2f", (h-b)*1024/n/1024; else print "?" }')" \
    | tee -a "$OUT/idle.tsv"
  kill "$client" "$pid" 2>/dev/null; wait "$client" "$pid" 2>/dev/null
}

echo "server cores: $SERVER_CORES ($NCORES) | load cores: $LOAD_CORES x$LOAD_THREADS | ${DURATION}s +${WARMUP}s warm-up | rounds: $ROUNDS | ring: $RING"
: >"$OUT/raw.tsv"; : >"$OUT/idle.tsv"
printf 'table\tcell\tserver\tround\treq/s\tcpu_s\tpeak_rss_kb\tmean\tmax\tfailed\n'

cell payload "GET /"        100 10 "http://127.0.0.1:PORT/"
cell payload "GET /1024"    100 10 "http://127.0.0.1:PORT/1024"
cell payload "GET /10240"   100 10 "http://127.0.0.1:PORT/10240"
cell payload "GET /65536"   100 10 "http://127.0.0.1:PORT/65536"
cell payload "POST 16K"     100 10 -d "$OUT/up16k.bin" "http://127.0.0.1:PORT/"
cell payload "POST 1M"      100 10 -d "$OUT/up1m.bin"  "http://127.0.0.1:PORT/"

for c in $CONNS; do
  cell conns "c=$c" "$c" 1 "http://127.0.0.1:PORT/"
done

echo
printf 'idle\tserver\tconns\tbase_kb\theld_kb\tKiB/conn\n'
idle popple
idle h2o

# Mean and spread per (table, cell, server).
echo
printf '%-8s %-12s %-7s %12s %8s %8s %12s\n' table cell server "req/s mean" "±%" cpu_s peak_rss_MB
awk -F'\t' '$5 ~ /^[0-9.]+$/ {
    k=$1 FS $2 FS $3; n[k]++; s[k]+=$5; c[k]+=$6
    if (!(k in lo) || $5<lo[k]) lo[k]=$5; if ($5>hi[k]) hi[k]=$5
    if ($7>rss[k]) rss[k]=$7; if (!(k in ord)) { ord[k]=++i; key[i]=k }
  } END {
    for (j=1;j<=i;j++) { k=key[j]; split(k, p, FS); m=s[k]/n[k]
      printf "%-8s %-12s %-7s %12.0f %8.1f %8.2f %12.1f\n", p[1], p[2], p[3], m, (hi[k]-lo[k])/m*50, c[k]/n[k], rss[k]/1024 }
  }' "$OUT/raw.tsv" | tee "$OUT/summary.txt"
rm -f "$OUT/up16k.bin" "$OUT/up1m.bin"
