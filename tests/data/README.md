# 测试数据来源

`fastdeploy-manifest.bin` 是从 AOSP `packages/modules/adb/fastdeploy/testdata/helloworld5.apk` 提取的二进制 `AndroidManifest.xml`，用于验证 fastdeploy package name 解析。

- AOSP project commit：`ce023afef190b0cea7f8939e9dd5ee3ee79b137b`
- SHA-256：`76c8292852c03bb13119d31c41c80fb40d5021987b0410e7cb86a94a681e7d23`
- 预期 package：`com.example.helloworld`

该夹具沿用 AOSP Apache License 2.0。
