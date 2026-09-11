# Windows USB 兼容说明

Windows 发行版只使用 `rusb` 的 vendored libusb backend。libusb 和 MSVC CRT 会静态链接进 `adb.exe`，发布目录不需要 `AdbWinApi.dll`、`libusb-1.0.dll`、`VCRUNTIME140.dll` 或其他本项目专用 DLL；当前项目也不提供 Windows 32 位构建目标。

## 驱动要求

单文件程序不等于无需设备驱动。Android USB ADB interface 必须由 WinUSB/libusbK 等 libusb 可访问的驱动绑定；设备管理器显示的 `AndroidUsbDeviceClass` 不是判断依据，应检查设备属性中的 `DEVPKEY_Device_Service`。本机已验证的三台设备都使用 `WinUSB` service，因此可由本程序直接访问。仍由旧 `AdbWinApi`/专用 Android USB service 占用的驱动不会自动转换为 WinUSB；若 libusb 能枚举 interface 但打开或 claim 返回 `Access`，server 会按官方注册 `no permissions ...; see [...]` 占位并在选择时返回 `insufficient permissions for device`，若驱动完全不向 libusb 暴露 interface，则程序仍无法列出该设备。

可以用 Zadig 或设备管理器为目标 Android interface 安装/切换 WinUSB。切换前应确认设备 serial、接口号和回滚方式；切换驱动会影响官方 ADB 及其他 Android 工具的访问。

## 构建与检查

只构建受支持的 64 位 Windows 目标：

```powershell
./scripts/build-standalone.ps1
target\dist\x86_64-pc-windows-msvc\adb.exe version
target\dist\x86_64-pc-windows-msvc\adb.exe server-status
```

脚本会把 Cargo 构建产物复制到独立发行目录，并要求该目录只有一个 `adb.exe`；随后自动调用 `check-standalone.ps1`，只允许 Windows 系统组件出现在 PE 导入表中。PDB、rlib 和 Cargo 缓存只保留在 `target\standalone`，不属于发行物。手工检查可以使用：

检查 PE 导入表时，除 Windows 系统组件外不应出现 `AdbWinApi.dll`、`libusb-1.0.dll`、`VCRUNTIME140.dll` 或 `adb-rust` 私有 DLL：

```powershell
./scripts/check-standalone.ps1 target\dist\x86_64-pc-windows-msvc\adb.exe
```

2026-07-20 的 release 实测导入仅包含 `kernel32.dll`、`bcryptprimitives.dll`、`ws2_32.dll`、`iphlpapi.dll`、`ntdll.dll`、`advapi32.dll`、`user32.dll`、`bcrypt.dll` 和 Windows API set，均为系统组件；最终 `target\dist\x86_64-pc-windows-msvc` 目录只包含独立的 `adb.exe`。当前包含 smart-socket 有序关闭、AOSP help 正文、mDNS 启动顺序和真实 S3 USB 身份恢复修复的构建 SHA-256 为 `f0bc2ed6a9bfe9960ade9b557f4fbc66bd8aa98ce5cfc74e1baea6f8486ac361`。

`bcrypt.dll`、`kernel32.dll`、`ws2_32.dll` 等系统 DLL 属于 Windows 平台本身，不能也不应打包到 ADB 发布目录。

Linux/macOS 的统一构建和依赖检查见仓库根目录的 `scripts/build-standalone.sh` 与 `scripts/check-standalone.sh`。Linux 要求完全静态时使用 musl；macOS 的 `libSystem`、CoreFoundation、IOKit 等系统框架属于操作系统边界，不作为发行目录中的额外扩展文件。

## 热插拔与睡眠恢复

后台周期枚举与 transport I/O 错误共同处理普通插拔；任一底层 packet 写失败都会关闭完整 transport，避免留下 zombie handle。`ADB_LIBUSB_START_DETACHED=1` 可要求启动时登记 detached 占位，之后通过 `attach` 重新枚举并恢复 transport。

Windows server 按 AOSP 创建不可见的顶层窗口和独立消息泵，监听 `WM_POWERBROADCAST/PBT_APMRESUMEAUTOMATIC`；启动流程会等待窗口创建完成后再报告 server 就绪，确保系统广播不会落在初始化竞态中。恢复后 server 关闭旧 USB transport、移除关联 forward，并立即重新扫描。部分旧设备在恢复后的首次枚举中可能暂时缺失或无法读取 serial descriptor，因此 server 会在 30 秒恢复窗口内按稳定 `devpath` 保留睡眠前 serial；transport 成功重新注册时立即清除该记录，超时后也会自动失效，避免永久掩盖真实设备更换。libusb bulk-in 使用短 timeout 轮询显式 close 标志，timeout 本身不会被当作断线。

## 当前验证结果与边界

当前 x64 静态发行版已在 API 28、34、36 三台真机上直接通过 vendored libusb 枚举并完成 `get-state`、`get-serialno`、`get-devpath` 和 shell；API 28 设备额外通过 push/pull SHA-256 一致性验证，server 重启后能重新枚举全部三台设备。空闲拔插、活动 shell 中拔出和 2 GiB `push -Z` 约 15% 处拔出均已实测：操作会及时失败，其他设备保持在线，不遗留 zombie transport、目标文件或同名临时文件，插回后设备可重新进入 `device`。

真实 S3 在 2026-07-20 完成三设备验证。第一次恢复暴露 API 28 `8b876adb` 首次枚举缺失后 serial descriptor 暂时不可读，导致错误退化为 `usb:001:019:2717:ff18:1`；改为 30 秒 `devpath -> serial` 恢复窗口后再次进入 S3，Windows 事件 `465721/465732` 分别确认进入与恢复，三台 transport id 从 `3/2/5` 重建为 `9/10/11`，serial 与 devpath 全部保持，三个 `get-state` 均返回 `device`，API 28 shell 也成功，fallback serial 未再次出现。AOSP `PowerTest.test_resume_usb_kick` 仍作为模拟恢复广播的补充门禁，不能替代该真实 S3 证据。AOSP `SocketTest.test_socket_flush` 已在 API 34/36 通过，证明远端 `A_CLSE` 时即使 smart-socket 仍有未读输入，也会先有序发送完整输出并排空输入，不在 Windows 上产生 TCP RST。SDK 中 `AdbWinApi.dll` 与 `AdbWinUsbApi.dll` 保持 `.disabled` 后缀时上述回归仍通过。

这些证据仍只覆盖当前机器的驱动组合和一次基线 S3 恢复。不同 Android 厂商驱动、真实 `NOPERMISSION`、多个 interface、反复睡眠循环、长时间睡眠及活动传输中睡眠仍需分别回归；单文件发布也不会自动修复 libusb 无权访问的设备驱动。

## 与官方 37.x USB 后端（libadbusb）的对比结论

官方 platform-tools 37.0.1（2026-07 Canary）在 Windows 上引入自研 `libadbusb` 取代 libusb 并设为默认，`ADB_USB_LEGACY=1` 回退旧后端；同版本 macOS 默认停用 libusb 改用原生 IOKit 后端（`ADB_LIBUSB=1` 可启用），Linux libusb 后端的热插拔改用 udev netlink 事件。官方 `adb server-status` 因此自报 `usb_backend: LIBADBUSB`（wire 值 4，2026-09-11 用 37.0.1 官方二进制在隔离端口实测；`mdns_backend: LIBADBMDNS` 同为实测值 3）。

截至 2026-09-11，`libadbusb` 未随 AOSP 开源：main 分支全仓库无 `adbusb` 命中，`Android.bp` 仍编译 `usb_libusb*.cpp`（Windows 同时保留 legacy `usb_windows.cpp`/AdbWinApi 源码），公开代码也没有 `ADB_USB_LEGACY` 环境变量，判断为 Google 内部后端。本仓库结论是**继续使用 rusb 的 vendored libusb，不更换**：

1. libadbusb 不可引入——未开源、无稳定 ABI，也没有可复用的 Rust binding。
2. USB 后端位于 wire 协议之下，官方换后端对设备侧和 smart-socket 语义零影响，不存在兼容性压力。
3. 本仓库的单文件静态发行（见上文导入表约束）与三真机回归、S3 恢复、热插拔、无权限占位等全部真实证据都构建在 vendored libusb 上，更换即全部作废且无用户可见收益。
4. libadbusb 解决的是 Google 规模下的 Windows 驱动矩阵与热插拔竞态问题；本仓库当前证据没有对应失败案例。

对齐动作：`server-status` 解码已支持官方 `LIBADBUSB`(4)/`LIBADBMDNS`(3) 枚举，本 server 自报 `LIBUSB`(2)/`LIBADBMDNS`(3)，官方客户端可正常解码；libusb bulk-in 短 timeout 轮询 close 标志的做法与官方 36.x"同步 API 重写"方向一致。若后续 libadbusb 开源进 AOSP main、本仓库驱动矩阵出现 libusb 无法修复的真实故障、或官方改变 `LIBUSB`(2) 的语义，再重新评估。
