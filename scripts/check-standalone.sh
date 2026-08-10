#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "用法: $0 ARTIFACT [--require-static]" >&2
    exit 2
}

artifact="${1:-}"
[[ -n "$artifact" ]] || usage
shift || true
require_static=0
if [[ "${1:-}" == "--require-static" ]]; then
    require_static=1
    shift
fi
[[ $# -eq 0 ]] || usage
[[ -f "$artifact" ]] || { echo "standalone check failed: 文件不存在: $artifact" >&2; exit 1; }

format=$(file -b "$artifact")
case "$format" in
    *"ELF"*)
        command -v readelf >/dev/null || { echo "standalone check failed: 需要 readelf" >&2; exit 1; }
        needed=$(readelf -d "$artifact" 2>/dev/null | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p')
        if [[ "$require_static" -eq 1 && -n "$needed" ]]; then
            echo "standalone check failed: ELF 仍包含动态依赖: $needed" >&2
            exit 1
        fi
        if [[ -n "$needed" ]]; then
            while IFS= read -r dep; do
                case "$dep" in
                    libc.so.*|libm.so.*|libgcc_s.so.*|libpthread.so.*|libdl.so.*|librt.so.*|libresolv.so.*|libudev.so.*|ld-linux*.so.*) ;;
                    *) echo "standalone check failed: 非系统 ELF 依赖: $dep" >&2; exit 1 ;;
                esac
            done <<< "$needed"
            echo "standalone check passed with system ELF dependencies: $needed"
        else
            echo "standalone check passed: 静态 ELF $artifact"
        fi
        ;;
    *"Mach-O"*)
        command -v otool >/dev/null || { echo "standalone check failed: 需要 otool" >&2; exit 1; }
        # BSD sed 不支持 GNU 的 \s，用 POSIX 字符类提取依赖路径。
        deps=$(otool -L "$artifact" | tail -n +2 | sed -E 's/^[[:space:]]+([^ ]+).*/\1/')
        while IFS= read -r dep; do
            [[ -z "$dep" ]] && continue
            case "$dep" in
                /usr/lib/*|/System/Library/*|/usr/lib/swift/*) ;;
                *) echo "standalone check failed: 非系统 Mach-O 依赖: $dep" >&2; exit 1 ;;
            esac
        done <<< "$deps"
        echo "standalone check passed with macOS system frameworks: $artifact"
        ;;
    *)
        echo "standalone check failed: 不支持的文件格式: $format" >&2
        exit 1
        ;;
esac
