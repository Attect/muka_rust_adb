/*
 * getentropy 兼容垫片（glibc 2.24 目标构建专用）。
 *
 * 背景：rustls/aws-lc-sys 引用 getentropy 符号，但 glibc 2.25 才提供该符号；
 * 用 zig（cargo zigbuild / zig cc）链接 glibc 2.24 存根时报
 * "undefined symbol: getentropy"（aws-lc/crypto/rand_extra/getentropy.c）。
 *
 * 用法（x86_64 为例，aarch64 把 target 换成 aarch64-linux-gnu.2.24）：
 *   zig cc -target x86_64-linux-gnu.2.24 -c scripts/getentropy-shim.c -o /tmp/getentropy-shim.o
 *   RUSTFLAGS="-C link-arg=/tmp/getentropy-shim.o" \
 *     cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.24 --bin adb
 *
 * 成功标志：objdump -T adb 的最大 GLIBC 符号 ≤2.18（历史发布基线），
 * 且 nm -D 无 getentropy 动态符号。
 */
#include <stddef.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

int getentropy(void *buffer, size_t length) {
    if (length > 256) {
        errno = EIO;
        return -1;
    }
    char *p = (char *)buffer;
    size_t left = length;
    while (left > 0) {
        ssize_t r = syscall(SYS_getrandom, p, left, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0) {
            errno = EIO;
            return -1;
        }
        p += r;
        left -= (size_t)r;
    }
    return 0;
}
