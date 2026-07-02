#!/usr/bin/env bash
# build_chain_c.sh — build the chain_c CLIs OUT-OF-SOURCE, under the notary home.
#
# Build artifacts are not source: they go to
#   ${BONSAI_CHAIN_C_BUILD:-${BONSAI_NOTARY_HOME:-$HOME/.local/trinote}/chain_c/build}
# (matching paths.chain_c_build_dir() in bsv_third_entry). Never into the checkout.
#
# Env:
#   BONSAI_CHAIN_C_BUILD  explicit build dir (wins)
#   BONSAI_NOTARY_HOME    state home (default ~/.local/trinote); build dir = $home/chain_c/build
#   BUILD_TYPE            CMake build type (default Release)
#   JOBS                  parallel build jobs (default 4)
# Flags:
#   --test   run ctest after building
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="${BONSAI_CHAIN_C_BUILD:-${BONSAI_NOTARY_HOME:-$HOME/.local/trinote}/chain_c/build}"
mkdir -p "$BUILD"
echo "== chain_c: $SRC  ->  $BUILD  (${BUILD_TYPE:-Release}, -j${JOBS:-4})"
cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE="${BUILD_TYPE:-Release}"
cmake --build "$BUILD" -j"${JOBS:-4}"
if [ "${1:-}" = "--test" ]; then
  ctest --test-dir "$BUILD" --output-on-failure -j"${JOBS:-4}"
fi
echo "chain_c CLIs -> $BUILD"
