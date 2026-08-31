#!/usr/bin/env bash
# Linux / GitHub Actions 构建脚本 (替代 Windows 的 build_pack.ps1)
#
# 依赖: Android NDK (r26+, 需支持 -std=c++23), zip
# 用法: ANDROID_NDK_HOME=/path/to/ndk ./build_pack.sh

set -u
set -o pipefail

log() { echo "[$(date '+%F %T')] $*"; }
abort() { echo "[$(date '+%F %T')] $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_ROOT:-}}}"
[ -n "$NDK" ] || abort "未找到 NDK, 请设置 ANDROID_NDK_HOME"

HOST_TAG="linux-x86_64"
case "$(uname -s)" in
    Darwin) HOST_TAG="darwin-x86_64" ;;
esac

CLANG="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/clang++"
SYSROOT="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/sysroot"
[ -x "$CLANG" ] || abort "clang++ 不存在: $CLANG"

TARGET="aarch64-none-linux-android29"
CPPFLAGS=(
    -std=c++23
    -static
    -s
    -O3
    -Wall -Wextra -Wshadow
    -fno-exceptions -fno-rtti
    -DNDEBUG
    -fPIE
)

log "编译中... target=$TARGET"
"$CLANG" "--target=$TARGET" "--sysroot=$SYSROOT" \
    "${CPPFLAGS[@]}" -Iinclude src/main.cpp -o magisk/Frozen \
    || abort "编译失败"

log "编译完成: $(ls -lh magisk/Frozen | awk '{print $5}')"

# 打包时排除历史产物 zip, 避免自包含
VERSION="$(sed -n 's/^version=//p' magisk/module.prop | head -1)"
ZIP_NAME="Frozen-${VERSION:-unknown}.zip"

log "打包中... $ZIP_NAME"
rm -f "magisk/$ZIP_NAME"
( cd magisk && zip -r9 -q "../$ZIP_NAME" . -x '*.zip' ) || abort "打包失败"

log "打包完成: $ZIP_NAME ($(ls -lh "$ZIP_NAME" | awk '{print $5}'))"
log "Everything OK"