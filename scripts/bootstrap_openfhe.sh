#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${1:-$ROOT_DIR/config/params_manifest.json}"
SOURCE_DIR="${OPENFHE_SOURCE_DIR:-$ROOT_DIR/_openfhe/source}"
BUILD_DIR="${OPENFHE_BUILD_DIR:-$ROOT_DIR/_openfhe/build}"
INSTALL_DIR="${OPENFHE_INSTALL_DIR:-$ROOT_DIR/_openfhe/install}"
JOBS="${BUILD_JOBS:-2}"

readarray -t VALUES < <(python - "$MANIFEST" <<'PY'
import json, sys
m=json.load(open(sys.argv[1], encoding='utf-8'))
print(m['openfhe']['repository'])
print(m['openfhe']['commit'])
PY
)
REPOSITORY="${VALUES[0]}"
COMMIT="${VALUES[1]}"

mkdir -p "$(dirname "$SOURCE_DIR")" "$BUILD_DIR" "$INSTALL_DIR"
if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  git clone --filter=blob:none "$REPOSITORY" "$SOURCE_DIR"
fi
git -C "$SOURCE_DIR" fetch --depth 1 origin "$COMMIT"
git -C "$SOURCE_DIR" checkout --detach "$COMMIT"

cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_STANDARD=17 \
  -DCMAKE_CXX_EXTENSIONS=OFF \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DWITH_OPENMP=ON \
  -DWITH_NATIVEOPT=OFF \
  -DBUILD_UNITTESTS=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_BENCHMARKS=OFF
cmake --build "$BUILD_DIR" --parallel "$JOBS"
cmake --install "$BUILD_DIR"

printf '%s\n' "$INSTALL_DIR"
