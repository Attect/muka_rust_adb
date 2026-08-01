# fastdeploy 设备端资产

本目录保存 AOSP `adb` fastdeploy 主机流程所需的设备端 agent。运行时会把这两个文件推送到 `/data/local/tmp/`，它们会参与本项目编译，不属于 `reference/` 离线参考副本。

- AOSP 路径：`packages/modules/adb/fastdeploy/`
- AOSP project commit：`ce023afef190b0cea7f8939e9dd5ee3ee79b137b`
- 构建目标：`aosp_arm64-aosp_current-userdebug`
- 构建命令：`source build/envsetup.sh && lunch aosp_arm64-aosp_current-userdebug && m deployagent`
- `deployagent.jar` SHA-256：`12f2c3a095ece48169fde287fe35c6b0018792e4adeebe02cba6a587a873192b`
- `deployagent.sh` SHA-256：`394e90c084880299d2b3e4d205241141f658f34ababea5db4fc17e3ea9e2229d`

代码及生成产物沿用 AOSP Apache License 2.0。更新 AOSP 参考版本时必须重新构建、替换两个资产并同步本文件中的 commit 与摘要。
