#!/usr/bin/env bash
#
# clean.sh — remove build artifacts for chain_c (libbonsai_chain + CLIs + tests).
#
# Usage:
#   ./clean.sh [--dry-run|-n] [--all|-a]
#     --dry-run   show what would be removed; remove nothing
#     --all       also remove stray in-source CMake files (if someone ran
#                 cmake from the project root by mistake)
#
# The out-of-source build/ dir is fully regenerable:
#   mkdir build && cd build && cmake .. && cmake --build . -j && ctest -LE net
#
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

DRY=0; ALL=0
for a in "$@"; do
  case "$a" in
    --dry-run|-n) DRY=1 ;;
    --all|-a)     ALL=1 ;;
    -h|--help)    sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "clean.sh: unknown option '$a' (try --help)" >&2; exit 2 ;;
  esac
done

# Regenerable build output.
TARGETS=(build)
# Defensive: stray in-source CMake artifacts (only with --all).
[ "$ALL" = 1 ] && TARGETS+=(CMakeCache.txt CMakeFiles cmake_install.cmake CTestTestfile.cmake Testing)

removed=0
for t in "${TARGETS[@]}"; do
  [ -e "$t" ] || continue
  sz=$(du -sh "$t" 2>/dev/null | cut -f1)
  if [ "$DRY" = 1 ]; then
    echo "would remove  $t  ($sz)"
  else
    echo "removing      $t  ($sz)"
    rm -rf -- "$t"
  fi
  removed=1
done

if [ "$removed" = 0 ]; then
  echo "clean: already clean (nothing to remove)"
elif [ "$DRY" = 1 ]; then
  echo "(dry run — nothing was removed)"
else
  echo "clean: done. Rebuild:  mkdir build && cd build && cmake .. && cmake --build . -j && ctest -LE net"
fi
