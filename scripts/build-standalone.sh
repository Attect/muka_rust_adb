#!/usr/bin/env bash
set -euo pipefail

default_target() {
    case "$(uname -s):$(uname -m)" in
        Linux:x86_64) echo "x86_64-unknown-linux-musl" ;;
        Linux:aarch64|Linux:arm64) echo "aarch64-unknown-linux-musl" ;;
        Darwin:x86_64) echo "x86_64-apple-darwin" ;;
        Darwin:arm64|Darwin:aarch64) echo "aarch64-apple-darwin" ;;
        *)
            echo "无法为当前主机自动选择 standalone target；请显式传入 target" >&2
            exit 2
            ;;
    esac
}

target="${1:-$(default_target)}"
target_dir="${CARGO_TARGET_DIR:-target/standalone}"

ensure_linux_uapi_headers() {
    local build_target="$1"
    local compiler_value="$2"
    local cflags_var="CFLAGS_${build_target//-/_}"
    local cflags_value="${!cflags_var:-${CFLAGS:-}}"
    local -a compiler_command=()
    local -a compiler_flags=()

    read -r -a compiler_command <<< "$compiler_value"
    [[ ${#compiler_command[@]} -gt 0 ]] || {
        echo "未能确定 $build_target 的 C 编译器" >&2
        exit 2
    }
    command -v "${compiler_command[0]}" >/dev/null 2>&1 || {
        echo "缺少 ${compiler_command[0]}；请安装 musl 工具链后再构建 $build_target" >&2
        exit 2
    }
    [[ -z "$cflags_value" ]] || read -r -a compiler_flags <<< "$cflags_value"

    if printf '#include <linux/magic.h>\n' |
        "${compiler_command[@]}" "${compiler_flags[@]}" -E -x c - >/dev/null 2>&1; then
        return
    fi

    # Debian 将 musl libc 头和 Linux UAPI 头分开安装，需要保持 musl 头优先。
    if [[ -r /usr/include/linux/magic.h ]]; then
        case " $cflags_value " in
            *" -idirafter /usr/include "*) ;;
            *) cflags_value="${cflags_value:+$cflags_value }-idirafter /usr/include" ;;
        esac
        export "$cflags_var=$cflags_value"
        read -r -a compiler_flags <<< "$cflags_value"
        if printf '#include <linux/magic.h>\n' |
            "${compiler_command[@]}" "${compiler_flags[@]}" -E -x c - >/dev/null 2>&1; then
            echo "提示: 使用 /usr/include 中由 linux-libc-dev 提供的 Linux UAPI 头。" >&2
            return
        fi
    fi

    echo "musl 编译器无法使用 <linux/magic.h>；请安装目标架构的 Linux UAPI 头（Debian: linux-libc-dev）" >&2
    exit 2
}

case "$target" in
    x86_64-unknown-linux-musl|aarch64-unknown-linux-musl)
        if ! rustup target list --installed | grep -Fxq "$target"; then
            echo "未安装 Rust target $target，请先执行: rustup target add $target" >&2
            exit 2
        fi
        cc_var="CC_${target//-/_}"
        compiler="${target%%-*}-linux-musl-gcc"
        if [[ -z "${!cc_var:-}" && -z "${CC:-}" ]]; then
            if [[ "$target" == "x86_64-unknown-linux-musl" && -z "$(command -v "$compiler" 2>/dev/null)" && -n "$(command -v musl-gcc 2>/dev/null)" ]]; then
                export "$cc_var=musl-gcc"
            elif ! command -v "$compiler" >/dev/null 2>&1; then
                echo "缺少 $compiler；请安装 musl 工具链后再构建 $target" >&2
                exit 2
            fi
        fi
        compiler="${!cc_var:-${CC:-$compiler}}"
        ensure_linux_uapi_headers "$target" "$compiler"
        ;;
    x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu)
        echo "提示: GNU 目标依赖系统 glibc；需要完全静态发行时请使用 musl。" >&2
        ;;
    x86_64-apple-darwin|aarch64-apple-darwin)
        if [[ "$(uname -s)" != "Darwin" ]]; then
            echo "macOS target 必须在 macOS 主机上构建: $target" >&2
            exit 2
        fi
        ;;
    *)
        echo "不支持的 target: $target" >&2
        exit 2
        ;;
esac

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"

# 避免 libusb1-sys 通过 pkg-config 探测并链接 libudev/系统 libusb。
PKG_CONFIG_LIBDIR="/__adb_rust_no_pkg_config__" \
PKG_CONFIG_PATH="/__adb_rust_no_pkg_config__" \
cargo build --release --target "$target" --target-dir "$target_dir"

build_artifact="$target_dir/$target/release/adb"
distribution_dir="$repo/target/dist/$target"
artifact="$distribution_dir/adb"
mkdir -p "$distribution_dir"
install -m 0755 "$build_artifact" "$artifact"

distribution_entries=$(find "$distribution_dir" -mindepth 1 -maxdepth 1 -print)
if [[ "$distribution_entries" != "$artifact" ]]; then
    echo "standalone distribution must contain only adb: $distribution_dir" >&2
    exit 1
fi

if [[ "$target" == *-musl ]]; then
    scripts/check-standalone.sh "$artifact" --require-static
else
    scripts/check-standalone.sh "$artifact"
fi
echo "standalone artifact: $artifact"
