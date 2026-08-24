#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENFHE_INSTALL_DIR="${OPENFHE_INSTALL_DIR:-$ROOT_DIR/_openfhe/install}"
BUILD_DIR="${DYNAMIC_CSSC_CPP_BUILD_DIR:-$ROOT_DIR/build/cpp}"
JOBS="${BUILD_JOBS:-2}"
cmake -S "$ROOT_DIR/cpp" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_PREFIX_PATH="$OPENFHE_INSTALL_DIR"
cmake --build "$BUILD_DIR" --parallel "$JOBS"
ctest --test-dir "$BUILD_DIR" --output-on-failure
printf '%s\n' "$BUILD_DIR"
