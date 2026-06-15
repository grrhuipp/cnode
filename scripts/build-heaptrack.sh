#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build-heaptrack}"
BUILD_TYPE="${BUILD_TYPE:-Profile}"
BUILD_ID="${BUILD_ID:-heaptrack-local}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Ninja}"

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "缺少构建工具: $1" >&2
        exit 1
    fi
}

if ldd --version 2>&1 | grep -qi musl; then
    echo "heaptrack 变体必须使用 glibc 环境，不能在 musl 上构建。" >&2
    exit 1
fi

require_tool cmake
require_tool git
require_tool file
require_tool ldd
if [ "$CMAKE_GENERATOR" = "Ninja" ]; then
    require_tool ninja
fi

cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -G "$CMAKE_GENERATOR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DBUILD_SHARED_LIBS=OFF \
    -DCNODE_MEMORY_STATS=ON \
    -DCNODE_HEAPTRACK_BUILD=ON \
    -DUSE_MIMALLOC=OFF \
    -DBUILD_ID="$BUILD_ID"

cmake --build "$BUILD_DIR" --parallel "${JOBS:-$(nproc)}"

"$BUILD_DIR/cnode" -v
file "$BUILD_DIR/cnode"
ldd "$BUILD_DIR/cnode"
