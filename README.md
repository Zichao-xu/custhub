# custhub

远程维护一批机器用的小网络。Windows（7 起）、macOS、Linux、OpenWrt 都能装，机器都在 NAT 后面也能互相找到；管理员凭主钥匙签的**通行证**，直接进任何一台的 shell、传文件、接它本机的端口。

它和别的东西的区别：

- **像 SSH 一样用，但不用开端口、不用跳板机。** `custhub sh A-2` 就进去了，不管 A-2 在哪个内网后面。
- **像 Tailscale 一样组网，但没有协调服务器。** 身份是每台机器的公钥，成员名单由主钥匙签名、在机器之间互传；找人、中转、打洞都由网里的机器互相帮忙，没有中心。
- **默认什么都不让做。** 名单里的成员之间，没有有效通行证也开不了 shell、传不了文件。通行证写明能进哪几台、能做什么、到什么时候。
- **一个静态程序**，C99，几百 KB，没有运行时依赖；密码学只用 [Monocypher](https://monocypher.org)。自己从 GitHub Release 升级，连不上网就自动回滚。

## 三分钟上手

**1. 机器接入**（在要被管的机器上跑一行）

```sh
curl -fsSL https://github.com/<owner>/<repo>/releases/latest/download/custhub3-join.sh | sh          # Linux / OpenWrt / macOS
```

```powershell
irm https://github.com/<owner>/<repo>/releases/latest/download/custhub3-join.ps1 | iex                # Windows 10 / 11, 管理员 PowerShell
```

装好后屏幕上显示**接入码**（形如 `R44-CQP`），告诉管理员。

**2. 管理员批准、签通行证**

```sh
custhub key unlock                                   # 输入 12 个词, 主钥匙进 ssh-agent(默认 8 小时)
custhub key approve R44-CQP                          # 批准, 自动编号 A-1、A-2 …
custhub key pass --to A-2 --hours 2                  # 给别人签 / 给自己签范围更小的(可选)
```

主钥匙解锁着的时候，本机连别的机器如果没有合适的通行证（过期、不含这台、不含这项服务），守护会当场给本机签一张（进全部机器、全部服务、2 小时）再连，过期了下次连接再签。所以对管理员自己来说，**解锁 = 能用**；上锁后不再自动签。

**3. 用起来**

```sh
custhub                                              # 终端界面: 机器列表, 选中回车开 shell
custhub sh A-2                                       # 进 A-2 的终端
custhub send ./a.zip A-2 /tmp/                       # 传文件过去
```

## 日常用法

### 看全局

```sh
custhub                                              # 终端界面(见下)
custhub ls                                           # 网里有谁、通不通
custhub inventory [--json]                           # 所有机器: 系统、机型、版本、能力、本机到它怎么连(读位置记录, 不连机器)
```

### 进机器、跑命令

```sh
custhub sh A-2                                       # 交互终端
custhub sh A-2 -- ipconfig                           # 跑一条命令, 退出码原样带回
custhub exec @online -- uptime                       # 多台并行跑; 目标: A-2 / A-2,A-7 / @all @online @win @win7 @linux @mac
custhub connect A-2 3389                             # 标准输入输出接到对方本机端口
ssh -o ProxyCommand="custhub connect %h 22" A-2      # 对方有 sshd 时, 22 当普通端口用
```

`exec` 走 shell 服务（要 sh 通行证），可加 `--json`、`--timeout 秒`。输出去掉终端控制码；输出和退出码都一样的机器合成一组显示。全部退出码为 0 才返回 0。Windows 上命令交给 `cmd.exe /c`，代码页已切成 UTF-8。

### 传文件

```sh
custhub send 本机文件 A-2 对方路径                   # 对方路径是已有目录或以 / \ 结尾, 就放进去、用原文件名
custhub pull 本机路径 A-2 对方文件                   # 本机路径是目录就放进去
```

本机路径永远在前，对方在后。通行证里有 `file` 或 `sh` 都行。支持中文和空格路径。传完按 BLAKE2b 核对整个文件，对不上就丢弃。断了再执行同一条命令就接着传（没收完的部分存为 `目标.<哈希前 8 位>.custhub-part`）。一次传一个文件。

### 看状况、测速、排查

```sh
custhub ping A-2                                     # 到它的各条直连(TCP IPv4 / IPv6、UDP)和延迟, 标出正在走的那条
custhub netcheck [A-2] [--json]                      # 网络状况: 地址、TCP / UDP 入站、UPnP、IPv6、打洞、各直连延迟
custhub bench A-2 [秒]                               # 上传、下载速度(走平常的加密流; 要 sh 通行证)
custhub log [A-2] [--grep 关键字] [--lines N]        # 日志; 不给名字是本机
```

看别的机器的 `netcheck`、`log` 是只读的，通行证里有 `info` 或 `sh` 都行。`ping`、`netcheck`、`bench`、`send`、`pull`、`inventory`、`exec` 都能加 `--json`。

### 等待、事件、告警

```sh
custhub wait A-2 version 0.3.49 [--timeout 秒]       # 等到条件成立: online offline reachable direct version; 超时返回 4
custhub watch [--json] [--notify]                    # 持续看事件: 上线、离线、版本、能力、直连
custhub alerts on | off | status                     # 这台电脑、当前用户: 登录时自动在后台 watch --notify
```

告警只提醒三件事：离线满 10 分钟、版本落后网里最新的满 30 分钟、能力变差。谁管机器谁开。登录自启动用系统自带的方式（Mac 登录项、Windows 登录时的计划任务、Linux 桌面自启动），通知也是（Mac 通知中心、Windows 10/11 系统通知、Linux notify-send；Win7 没有系统通知）。终端界面的提示行也显示告警。

### 终端界面

直接敲 `custhub`：机器列表（在线没有、版本、能力、直连还是经哪台转、TCP / UDP），选中按 Enter 开 shell，`v` 看本机通行证，`i` 装别人发来的通行证。按 `u` 解锁主钥匙后多出管理功能：`a` 批准待接入的机器、`s` 签通行证、`n` 新机器的一行接入命令、`d` 移出名单、`l` 上锁。

### 给 AI 用

说明书在 `skills/custhub/SKILL.md`（Claude Code 的 skill 格式，其他 AI 也能当说明书读）：先 `inventory --json` 看全局，用 `exec` 而不是往终端里灌按键，被拒时请人签通行证。

## 接入的细节

**从网里的机器装（Win7 也行）**：管理员跑 `custhub line`（或界面里按 `n`）得到一行命令，地址是网里一台从外面连得进来的机器：

```
powershell -c "start powershell -verb runas -args '-NoExit -c iex(New-Object Net.WebClient).DownloadString(''http://IP:8444/ps1'')'"; curl -fsSL http://IP:8444/sh|sh
```

Windows 在 Win+R / cmd / PowerShell 里粘贴（弹 UAC），Mac / Linux 在终端里粘贴。每台机器都缓存最新版的全部发布物（各平台程序、接入脚本、源码，清单由主钥匙签名），在监听端口上用只读 HTTP 照 GitHub Release 的路径发出去，所以连不了 GitHub HTTPS 的机器也能装。注意普通 HTTP 不防半路调包：接入脚本会按清单核对程序的 sha512，但脚本本身没有校验。

**装了什么**：接入脚本下载本平台程序（GitHub 连不上时走镜像），按发布清单核对 sha512，装进系统目录、注册成系统服务，向网里报到。`custhub` 命令加进 PATH（Linux / macOS `/usr/local/bin`，OpenWrt `/usr/bin`，用户模式 `~/.local/bin`，Windows 把安装目录加进系统 PATH）。

**本机谁能用**：跑接入的账号（用 sudo 时是 sudo 之前的账号）加进本机的 `custhub` 用户组，重新登录后不用 sudo 就能 `sh / connect / ls / pass`。别的账号用 `sudo custhub user add <账号>` 加（`user del` 移出，`user ls` 列出）。组里的账号碰不到节点钥匙，但能用本机的通行证进别的机器，只加可信的人。`join`、`remove`、`user`、`key` 要 root，不是 root 时自动换成 sudo（Windows 上提示用管理员终端）。

**卸载**：`custhub remove`（服务、PATH、安装目录一起撤）。

## 管理员

管理员自己的电脑用**用户模式**装（装在 `~/.custhub`，用自己账号的登录项跑，不要 root）：

```sh
custhub join --user --github <owner>/<repo>
```

```sh
custhub key unlock | lock | status
custhub key pending                                  # 待批准的机器, 带接入码
custhub key approve R44-CQP [名字]                   # 批准; 不给名字就自动编号(对方机器名记进备注)
custhub key rename A-3 office-pc                     # 改名(编号不会再分给别人)
custhub key remove office-pc                         # 移出名单
custhub key pass --to A-2,A-7 [--for 人] [--svc "sh file port:3389 info"] [--hours 2]
custhub line                                         # 新机器的一行接入命令
```

**给工程师开权限**：

1. 工程师电脑照常接入（自己的 Mac 建议用户模式：`curl … | CUSTHUB_JOIN_ARGS=--user sh`），把接入码给管理员。
2. 管理员：`custhub key approve <接入码> zhang`，再 `custhub key pass --for zhang --to web1,web2 --hours 8`，把得到的 `zhang.pass` 发给工程师。
3. 工程师：`custhub pass zhang.pass`，然后 `custhub sh web1`。`custhub pass` 不带参数列出本机的通行证和剩余时间。

通行证里的服务：`sh`（终端、跑命令、测速）、`file`（传文件）、`info`（只读看网络状况和日志）、`port:N`（接本机端口）。`sh` 包含 `file` 和 `info`。默认 2 小时，最长 1 天。

### 第一次建网

1. `custhub key unlock`：还没有节点时会打印由口令推出的主公钥。
2. 每台准备当种子的机器（有公网地址的服务器）上 `custhub keygen /opt/custhub/node`，管理电脑上 `custhub keygen ~/.custhub/node`，记下公钥。
3. 写第一份名单正文，签名，出种子：
   ```
   custhub-mesh-trust 1
   node  seed1 <公钥> <公网地址>:8444
   node  admin <公钥>
   --end--
   ```
   ```sh
   custhub key sign-trust 正文 --master "ssh-ed25519 AAAA…" --out trust
   custhub key seed --trust trust --master "ssh-ed25519 AAAA…" --github <owner>/<repo> --out custhub3.seed
   ```
4. 发版（见「开发」），然后种子机器、管理电脑照常接入。种子机器要在防火墙 / 安全组放行 TCP 和 UDP 8444。

名单里的地址只在第一次建网时用（老写法 `relay <名字> <公钥> <地址>` 照样认）。之后名单只管谁是成员，每次改名单都会顺手去掉这些地址。

## 原理

### 找人：可达、地址簿、种子

- **可达**由各台机器自己判断：回连自检通过，再过观察期（默认 5 分钟，期间每分钟回连测一次，中途不通就从头算），就在**位置记录**里声明。能用 UPnP 时自动在路由器上开端口；同一局域网里多台都要用 8444 时自动顺延，不会撞。
- **地址簿**（节点目录下的 `peers`）：每台把见过的可达地址记下来，重启后靠它找人。上次就可达的机器重启后免观察期；观察期中重启（比如升级），已观察的时长接着算（`obs`）。
- **种子**：发出去的种子附上地址簿里的可达地址（`hint` 行），新机器接入后记进自己的地址簿。地址错了不要紧，握手时核对公钥。一台机器谁都连不上超过 1 分钟时，自己去发布源取最新的 `custhub3.seed`。
- 「可达」只用在一件事上：新机器第一次接触网时找得到它。别的协助（中转、查映射、接待报到、接待访客）每个节点都能做。

### 直连：局域网、打洞、UDP、双栈

能直连就直连，连不上才经别的机器中转。规则对所有机器一样，没有特例。

- **局域网直连**：监听所有地址的机器把自己各个局域网 IPv4 地址写进位置记录（`端点=`），别的机器把它和公网地址一起轮流试，通了就留下。同一局域网的机器自然走局域网。只有局域网端点、对方又不可达时，重试间隔放长到 1 分钟。
- **TCP 打洞**：两台都连不进来时，各自用固定的打洞端口（监听端口 + 10）去问两台不同的成员「我在公网上是什么地址」（STUN，`/whoami`），两次一样才写进位置记录（`打洞=`），不一样就是对称型 NAT，不报。双方都有打洞端点时，在同一个时间窗里（每 15 秒的前 6 秒）每秒互拨，握手包交错时两边 NAT 都开了口，合成一条 TCP。公钥小的一方当 Noise 发起方。
- **UDP 链路（热备）**：每台在 TCP 监听的同一个端口号上开 UDP，和每个在线成员都挂一条 UDP 链路，里面跑 KCP（`vendor/ikcp.c`，流模式，MTU 1200）上的同一套 Noise 握手和帧。地址轮流试局域网端点、可达地址、UDP 打洞端点。平时流量走 TCP，TCP 断了新流量马上落到 UDP，不用重新拨号。UPnP 同时映射 UDP，并请一台不在同一局域网的成员发带暗号的包验证，收到了才报「UDP 入站开着」，每 10 分钟复查。
- **双栈热备**：本机有公网 IPv6 时同时监听 IPv4 和 IPv6，两种地址分开做自检、分开算可达。对方两种都通时两条链路都挂着，新流量优先走 IPv6，断了马上落到 IPv4。声明的是网卡上的固定 IPv6 地址，不用临时地址。Windows 启动时在防火墙里放行自己。conf 可用 `listen6` / `announce6` 指定。
- **中转**：没有直连时，对方直连着的成员里本机也直连着谁，就挑延迟最低的那台经它转，它可不可达都行。转发的流里再套一层端到端加密，转发的机器只看得到谁连谁。

### 选路、速度、自修

- **按延迟选路**：每条直连都用带时间戳的心跳测来回延迟（有流量时每 5 秒测一次）。新连接挑最近 30 秒里最低延迟的那条，偏好 IPv6 > IPv4 > UDP：IPv4 要比 IPv6 快 20ms 以上才换，UDP 要比 TCP 快 5ms 以上才换。
- **窗口自动调整**：每条流起步给对方 256KB 在途额度，收方消费得过来就翻倍，最多 8MB，所有流合计最多多给 64MB。来回 50ms 的线路从约 5 MB/s 提到约 50 MB/s。
- **网络变化马上重连**：每 2 秒看一次本机地址，一变就重查映射、UPnP、回连测试，重新拨号、重新挂 UDP；各条链路立刻发心跳，3 秒内没回音的关掉。
- **UPnP 自修**：路由器说映射着、回连却不通时（比如路由器防火墙重载清掉了转发规则），删掉映射重新申请，最多 5 分钟一次。

### 升级与兼容

- **自升级**：每台机器自己从 GitHub Release 拉签名的发布清单；网里已有新版的机器就先从网里取，取不到再去 GitHub。每台只留最新版，缓存全部发布物，旧版本自动删掉。换上后试用，连不上网络就自动回滚。
- **功能协商**：每台在位置记录里报自己支持哪些功能（`|f=`，`inventory --json` 的 `features`）。用某个功能前先看对方有没有，没有就当场说「对方还不支持」，不按版本号猜，新旧版本混跑也不会误判。

## 安全模型

- **链路**：TCP / KCP 上跑 Noise IK（X25519 / ChaCha20-Poly1305 / BLAKE2b），只收名单里的公钥。经别的机器转发的流再套一层端到端 Noise。
- **签名**：名单、发布清单、通行证、种子都用主钥匙签，格式同 `ssh-keygen -Y sign`（ssh-keygen 也能验）。
- **通行证**：绑定持有人的节点公钥，写明能进哪些机器、能用哪些服务、有效期，对方自己验，不问任何中心。名单外的机器持证也能挂进网里当访客，只能连通行证里写的机器。
- **主钥匙**：12 个词 → scrypt(N=2^17, r=8, p=1) → ed25519；私钥不落盘，只在 ssh-agent 里。没有特权机器：批准、签证、发版都只认主钥匙。
- **本机**：节点钥匙、通行证、日志只给 root / 管理员。`custhub` 组只能读 conf 和控制口令牌（POSIX：节点目录 0710、这两个文件 0640 root:custhub；Windows：本地组 custhub 只对这两个文件可读）。本机控制口要出示每次启动随机生成的令牌。

## 平台

| | 服务 | shell |
|---|---|---|
| Linux（x86_64 / arm64 / armv5 / mips / mipsel，静态 musl） | systemd | 伪终端 |
| OpenWrt | procd | 伪终端 |
| macOS（arm64 / x86_64） | launchd | 伪终端 |
| Windows 10 1809 及以上（x64 / x86） | 计划任务（SYSTEM） | 交互用 ConPTY，跑命令用管道 |
| Windows 7 / 8 / 8.1（x64 / x86，补丁模块 `plat_win7.c`，链 msvcrt） | 计划任务（SYSTEM） | 管道 + 守护这边做行编辑回显（没有 ConPTY）；没有终端界面 |

## 开发

```sh
./build.sh                                           # 本机编一份 ./mesh(就是 custhub, 测试用)
./build.sh release                                   # 交叉编译全部发布目标(要 zig) → dist/out/
./linux-test.sh [套名 …]                             # Debian 容器里并行跑全部 POSIX 验收(约 2.5 分钟; JOBS=并行数)
dist/ship.sh "说明"                                  # 发版: 提交干净、全套验收全过 → 同步公开仓库 → release.sh
dist/release.sh <owner>/<repo> [--dry]               # 只发版: 编、签发布清单和种子(主钥匙要已解锁)、gh release create
```

### 测试

| 测试 | 内容 |
|---|---|
| `purity.sh` | 核心文件里没有条件编译、只用 C99 标准头文件（系统差异只在平台模块） |
| `pass-test.sh` | 通行证：验与签 |
| `test.sh` | 两台可达节点 + NAT 后节点 + 访客：连通、大流量、转发方读不到内容、换节点、换地址、兜底、拒绝 |
| `role-test.sh` | 可达自检、观察期、报到 / 批准 |
| `lan-test.sh` | 局域网直连：不可达的两台靠各自报的局域网端点连上 |
| `punch-test.sh` | TCP 打洞：查映射、端点随位置记录传开、两台不可达的同时拨直连（iptables 丢 RST 模拟 NAT） |
| `udp-test.sh` | UDP 链路：查映射、打洞、KCP 上跑握手和帧；丢 20% 的包 1MB 原样到达 |
| `v6-test.sh` | 双栈：IPv4、IPv6 分开算可达；两条链路热备，优先 IPv6，断了马上走 IPv4 |
| `net-test.sh` | 心跳测延迟、`ping` / `netcheck`、网络变化马上重连、高延迟下窗口自动调整 |
| `decentral-test.sh` | 去中心化：唯一的可达节点关掉后经不可达节点中转；新机器向不可达节点报到 |
| `file-test.sh` | 传文件：send / pull、放进目录、中文和空格路径、断了续传、内容核对、权限 |
| `exec-test.sh` | inventory、exec 多台并行、合并相同输出、退出码、`--json`、超时、不在线、没权限 |
| `alerts-test.sh` | 告警：on 写好自启动并马上起来、status、off 去掉并停掉 |
| `sh-test.sh` | shell：命令、退出码、大输出、交互、窗口大小、Ctrl-C、收尾 |
| `upnp-test.sh` | UPnP 自动映射（假路由器） |
| `rel-test.sh` | 发布物：GitHub、网内取包、缓存、只读 HTTP、只留最新版、灰度、坏 sha512、回滚 |
| `join-test.sh` | 接入（演练模式，不碰系统）、用户模式、权限、控制口令牌、卸载 |
| `admin-test.sh` | 管理端：解锁（和参考实现对照）、批准、移除、种子、发布清单、第一次建网 |
| `group-test.sh` | 本机谁能用：custhub 组、`user add / del`（要 root，只在容器里跑） |
| `tui-test.sh` | 终端界面：伪终端里按键，列表、批准、签证 |
| `dist-test.sh [win主机 本机地址]` | 一行命令的引导脚本 |
| `win-test.sh` / `win-cross-test.sh` / `win-install-test.sh` / `posix-install-test.sh` | 实机：Windows 平台模块、跨机器、真装 → 升级 → 卸载 |

### 代码分层

| 层 | 文件 |
|---|---|
| 命令行、界面、控制口 | `main.c` `tui.c` `app.c` |
| 给人和 AI 的工具 | `exec.c`（多台跑命令）`file.c`（传文件）`bench.c`（测速）`info.c`（只读查看）`events.c`（事件、告警） |
| 服务（shell / 端口 / 取包） | `svc.c` `sh.c` `rel.c` |
| 通行证 | `pass.c` |
| 连通（链路、转发、找人、自检、打洞、UDP、UPnP） | `link.c` `hop.c` `disc.c` `qual.c` `punch.c` `udp.c` `upnp.c` |
| 身份（握手、签名、口令派生） | `noise.c` `sig.c` `sshsig.c` `kdf.c` `b64.c` |
| 部署 / 管理端 | `join.c` `key.c` |
| 公用 | `util.c` |
| 平台模块（编译时选一个） | `plat_posix.c` / `plat_win.c` + 版本模块 `plat_win10.c` 或 `plat_win7.c`，接口 `plat.h` |

## 许可证

GPL-3.0。`vendor/` 里的 Monocypher 是 CC0-1.0 / BSD-2-Clause 双许可（见 `vendor/LICENCE.md`）；KCP（`vendor/ikcp.c`，1.7 版）是 MIT 许可（见 `vendor/LICENSE-kcp`）。
