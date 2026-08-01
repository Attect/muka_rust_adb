# AOSP adb 参考源码

本目录保存少量从本机 AOSP 工作树复制的 adb 官方源码，只作为协议与 CLI 行为对照，不参与本项目编译。

- 来源路径：`/mnt/wsl/PhysicalDrive5/Android/aosp`
- Windows 访问路径：`\\wsl.localhost\Debian\mnt\wsl\PhysicalDrive5\Android\aosp`
- 来源提交：`c77ad311af14245c4102bce7d4c1be25b872c10a`
- 来源分支：`master`
- 复制时间：`2026-07-07`

当前复制范围聚焦已实现或正在调试的边界：

- `client/commandline.cpp`、`client/commandline.h`：CLI 参数解析、`shell`、`abb`、常见 host command 行为。
- `adb_utils.cpp`、`adb_utils.h`、`adb_utils_test.cpp`：官方 `escape_arg` 行为和测试样例。
- `shell_service_protocol.cpp`、`services.h`、`daemon/shell_service.cpp`、`daemon/services.cpp`：shell v2 service string 与 packet 协议行为。
- `client/main.cpp`：server main 启动、`fork-server --reply-fd` 的官方 `OK\n` ACK 语义。
- `client/file_sync_client.cpp`、`daemon/file_sync_service.cpp`、`daemon/file_sync_service.h`、`file_sync_protocol.h`、`docs/dev/sync.md`：`sync:` v1/v2 wire format、压缩 flag、`QUIT` 关闭语义，以及 daemon 端 `secure_mkdirs`/capabilities 处理边界。
- `adb_listeners.cpp`、`adb_listeners.h`、`adb_listeners_test.cpp`、`socket_spec.cpp`、`socket_spec.h`、`socket_spec_test.cpp`：forward/reverse listener registry、local 端点唯一性、`tcp:0` 解析和 socket spec 行为。
- `client/detach.cpp`、`client/detach.h`、`client/transport_usb.cpp`、`client/usb.h`、`client/usb_libusb*.cpp/h`、`client/usb_windows.cpp`、`client/usb_linux.cpp`、`client/usb_osx.cpp`：USB host backend、libusb attach/detach 生命周期、`ADB_LIBUSB_START_DETACHED` 边界和 native backend 差异。
- `adb.h`、`adb.cpp`、`sockets.cpp`、`socket.h`、`transport.cpp`、`transport.h`：`A_OPEN/A_OKAY/A_WRTE/A_CLSE`、`delayed_ack`、transport feature 协商等行为。

新增兼容性实现时，优先在本目录中定位官方行为，再把结论落实到本项目的协议、服务或 CLI 测试中。
