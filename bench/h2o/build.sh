#!/usr/bin/env bash
#
# Build the libh2o reference server. h2o itself is built out of tree, library
# only — no `h2o` binary, no mruby — so the whole thing stays a few hundred MB:
#
#   git clone --depth 1 https://github.com/h2o/h2o.git /tmp/h2o-src
#   cmake -S /tmp/h2o-src -B /tmp/h2o-build -DCMAKE_BUILD_TYPE=Release \
#         -DWITH_MRUBY=OFF -DWITH_BROTLI=OFF -DWITH_ZSTD=OFF
#   make -C /tmp/h2o-build -j8 libh2o-evloop
#   bench/h2o/build.sh
set -euo pipefail

SRC=${H2O_SRC:-/tmp/h2o-src}
BUILD=${H2O_BUILD:-/tmp/h2o-build}
HERE=$(cd "$(dirname "$0")" && pwd)

incs=(-I"$SRC/include" -I"$SRC/deps/picotls/include" -I"$SRC/deps/quicly/include"
      -I"$SRC/deps/picohttpparser" -I"$SRC/deps/klib" -I"$SRC/deps/yoml" -I"$SRC/deps/yaml/include"
      -I"$SRC/deps/golombset" -I"$SRC/deps/cloexec" -I"$SRC/deps/libyrmcds" -I"$SRC/deps/hiredis"
      -I"$SRC/deps/libgkc" -I"$BUILD")

cc -std=gnu99 -O2 -pthread -D_GNU_SOURCE -DH2O_USE_LIBUV=0 -DQUICLY_USE_TRACER=1 \
   "${incs[@]}" -o "$HERE/server" "$HERE/server.c" \
   "$BUILD/libh2o-evloop.a" -lssl -lcrypto -lz -lm -ldl -pthread
echo "built $HERE/server"
