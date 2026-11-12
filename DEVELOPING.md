# 开发文档

本文档面向开发者，使用说明见 [README.md](README.md)，部署见 [android/README.md](android/README.md)。

当前版本 **v3.9**，开源前已经过二十余轮调试和优化。

## 仓库结构

|目录|内容|
|-|-|
|`android/`|手机应用，Kotlin 编写，当前主线|
|`pc/`|早期 PC 端工具，Python 编写，功能已被应用取代|
|`docs/`|面向使用者的两篇文档：威胁模型、能力边界|
|`tools/`|无 Android Studio 时的命令行工具链安装脚本|

`pc/linkguard/rules.py` 包含判定逻辑，业务规则最早在那里成型。

## 环境

* JDK 17 以上（实际用 21 构建通过）
* Android SDK：Platform 35、Build-Tools 35.0.0
* Gradle 8.9，AGP 8.7.3，Kotlin 2.0.21
* `minSdk` 与 `targetSdk` 均为 35
* `pc/` 需要 Python 3.9 以上

仓库自带 Gradle Wrapper（8.9），首次构建会自动下载发行包，不需要预装 Gradle。只缺 Android SDK 时执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\setup-android-sdk.ps1
```

## 构建与测试

```powershell
cd android
.\build.ps1
```

脚本先跑单元测试，通过后才打包，产物在 `android\app\build\outputs\apk\debug\app-debug.apk`。工具链从 `JAVA_HOME`、`ANDROID_HOME` 与 `local.properties` 依次查找，缺失时直接报错并说明该怎么补；Gradle 用仓库内的 `gradlew`。

手动执行：

```bash
cd android
gradle test
gradle assembleDebug
```

可以直接用 `.\gradlew test`、`.\gradlew assembleDebug`，与脚本等价。

测试共 75 个，全部是纯 JVM 的 JUnit 4，不需要真机，也不需要 Robolectric。

|测试类|覆盖|
|-|-|
|`DomainSetTest`|域名后缀匹配、用户输入清洗|
|`DnsMessageTest`|报文解析与合成、EDNS 钳制、应答裁剪、TC 位|
|`Ipv4Test`|IPv4 与 UDP 拆装、校验和|
|`DnsProxyTest`|应答包地址与端口是否正确对调|
|`GuardEngineTest`|判定顺序|
|`SmartModeTest`|智能模式各类规则的命中与豁免|
|`ObserveModeTest`|排查模式确实零拦截|
|`LearnedFilterTest`|学习结果的折叠、剔除与上限|

## 数据流

```
┌──────────────── Android 进程 ────────────────────────────┐
│  VpnService                                              │
│    ├─ Builder: addAddress(10.111.111.2/32)               │
│    │          addDnsServer(10.111.111.1)                 │
│    │          addRoute(10.111.111.1/32)   ← 只路由 DNS    │
│    ├─ 读线程从 tun 取 IP 包，交给 16 路线程池             │
│    └─ 工作线程：                                          │
│         Ipv4.parseUdp → DnsMessage.parseQuestion          │
│              → GuardEngine.decide(host)                   │
│                    ├─ 拦截 → 本地合成 NXDOMAIN            │
│                    └─ 放行 → 转发上游 → fitUdp → 写回 tun │
│                                                          │
│  UI：MainActivity / ApprovalsActivity / PinActivity       │
│  Prefs · BlockLog · Stats · LearnedLog · LearnedFilter    │
└──────────────────────────────────────────────────────────┘
```

`DomainSet`、`DnsMessage`、`Ipv4`、`DnsProxy`、`GuardEngine`、`SuspiciousRules`、`LearnedFilter` 不 import `android.*`，可以在电脑上直接跑测试。修改这些文件时请保持该约束，这是整个项目里唯一能低成本验证的部分。

`GuardVpnService`、`Prefs`、`BlockLog`、`Stats`、`LearnedLog`、三个 Activity 与 `Ui.kt` 依赖 Android，只能靠真机验证。为降低盲写风险，这些地方的关键路径都做了计数。

## 排查手段

没有 adb 日志时依赖三个工具。

**Stats 计数器**：收包、应答、非 DNS、解析失败、上游失败、写回失败、TCP 回退、重启次数。主界面的「检查网络与拦截状态」会完整输出。

**`rawDnsLookup()`**：手工构造 DNS 报文直连 `10.111.111.1:53`，绕开 `InetAddress` 的缓存，测到的是真实链路。

**`probeUpstream()`**：直接向每个配置的上游发查询，用于区分"上游不可达"与"我们的转发有问题"。

读数对应关系：

|现象|结论|
|-|-|
|收包为 0|查询没有进入隧道，检查路由与 DNS 配置|
|收包大于 0 而应答为 0|解析环节把所有包都拒了|
|上游失败持续增长|转发链路有问题|
|写回失败不为 0|包过大，或 tun 写入失败|

## 设计决定

修改以下行为前先看理由。

* **只路由 `10.111.111.1/32`**，不接管全部流量。看不到路径与内容，但转发实现出错时不会导致整机断网，也不影响耗电。
* **每个查询开独立的 `protect()` socket**。共用 socket 时并发线程会收到彼此的应答，DNS 结果随机错乱。开 socket 的开销相对一次网络往返可以忽略。
* **16 路线程池加 120 秒应答缓存**。早期单线程串行，一个网页并发解析几十个域名会全部排队超时，表现为页面能开但图片全白。
* **上游优先用当前网络的 DNS**，公共 DNS 只作备用。部分家用网络到不了 `223.5.5.5`，那时所有放行的查询都会失败。
* **转发前把 EDNS 载荷上限钳到 1232**。否则上游可能返回超过隧道 MTU 的应答，整包被内核丢弃。
* **上游应答带 TC 位时自行用 TCP 回查**。客户端收到 TC 会改连我们的 TCP，而服务不监听 TCP，那条连接必然超时，因此截断必须在服务端消化。
* **`fitUdp` 把应答裁到 1400 字节以内并清除 TC 位**，保留尽可能多的完整资源记录，丢弃授权段与附加段。
* **拦截时本地合成 NXDOMAIN**，不向上游发查询。这是"连接从未建立"的前提。
* **判定顺序为 deny、allow、模式规则**。黑名单必须优先，否则被误加进白名单的广告域名会失效。
* **广告黑名单只在严格模式启用**。名单包含 `umeng.com`、`mob.com`，后者是 ShareSDK，不少应用的短信验证码依赖它。智能模式的定位是不影响应用可用性。
* **切换模式只换判定引擎，不重建 VPN**。重建会重新下发 DNS 配置，系统缓存随之失效，刚放行的网站会立刻被拦。
* **学习流程为记录、清洗、一次确认**。`LearnedLog` 仅在自动学习期间记录放行的域名；`LearnedFilter` 负责折叠子域、剔除广告域、跳过已在名单的条目、封顶 60 条。界面只让用户做一个决定。
* **PIN 保护切换模式与网站管理，不保护关闭保护**。留一条紧急停用的路径，代价是防护本身可以被关掉。

## 已知缺陷与教训

这些问题都真实发生过，修改相关代码时不要回退。

|现象|根因|对策|
|-|-|-|
|统计全绿但所有网站解析失败|应答包 `dstIp` 误用请求的 `dstIp`（即自身地址），应为 `srcIp`，每个应答都被发回隧道自身|地址端口对调抽成 `DnsProxy` 并加回归测试|
|页面能开但图片全白|DNS 单线程串行，并发查询全部排队超时|并发量是功能需求|
|部分域名解析失败|上游返回 TC=1 后客户端改走 TCP，服务只处理 UDP|检查截断路径|
|TC 位判断错误|TC 位在 flags 第一个字节（`0x02`），写到了第二个|标志位对照 RFC 写测试|
|EDNS 钳制不生效|测试夹具的 OPT 记录拼错，域名应为 1 字节、type 应为 2 字节|夹具同样按协议写|
|PC 端整体拦截 GitHub|hosts 文件的行内注释被当成域名|解析名单时先切掉行内注释|
|批量替换污染了 6 个源文件|PowerShell 中单元素数组取 `$p[0]` 得到的是字符而非整串|批量替换前先初始化 git，脚本需校验命中数|

## 未完成的工作

* 不监听 TCP DNS。客户端强制走 TCP 时无法应答，目前靠 EDNS 钳制与服务端 TCP 回查规避大部分情况。
* 不处理 IPv6 的 DNS。少数场景会解析失败，需要补 IPv6 地址与路由，并扩展 `Ipv4`。
* `minSdk` 为 35，只能安装在 Android 15 及以上，覆盖面窄。降到 29 需要回归验证 VPN 行为。
* 使用 debug 签名发布，任何人都能用同一 keystore 覆盖安装。正式发布前应改用 release keystore。
* 名单不能远程更新，加域名必须到手机上操作。这是经过取舍之后的行为，避免应用上传任何数据。
* 反查域名（`in-addr.arpa`）会在日志里产生噪音，可以静默丢弃。
* 没有 CI，回归靠本地执行。应增加 GitHub Actions 跑 `gradle test`。
* 没有无障碍能力，看不到页面内容，无法识别同一域名下的仿冒页。评估过稳定性和隐私代价，暂不实现。

## 发布

1. 修改 `android/app/build.gradle.kts` 中的 `versionCode`（每次加一）与 `versionName`
2. 生成 release keystore 并配置，keystore 与密码不要提交；`.gitignore` 已排除 `*.jks` 与 `*.keystore`
3. 执行 `gradle test`，全部通过后执行 `gradle assembleRelease`
4. 新建 GitHub Release，只上传当前版本的 APK；`dist/` 已被 `.gitignore` 排除
5. 同步 README 中的三个数字：版本号、内置名单条数（`BuiltinRules.ALL.size`）、单元测试数

## 代码风格

* 注释用中文
* 界面用代码构建，不用 XML 布局，减少资源 ID 与布局文件这两层出错点
* 运行时零第三方依赖，仅使用 Kotlin 标准库；新增依赖需要说明必要性
* 纯逻辑层不得 import `android.*`，否则失去可测试性
* 提交前确认 `gradle test` 通过；改动判定逻辑必须补测试

报告问题时请附手机型号、Android 版本、护链版本号，以及「检查网络与拦截状态」的整页输出。

## 许可

MIT，见 [LICENSE](LICENSE)。`pc/` 运行时下载的第三方域名名单各自遵循原始许可，见 [pc/README.md](pc/README.md)。

