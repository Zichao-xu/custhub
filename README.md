# custhub

远程维护一批机器（Windows / macOS / Linux / OpenWrt）用的小网络：机器都在 NAT 后面也能互相找到，管理员凭**主钥匙签的通行证**直达任何一台的 shell 和本机端口，不依赖 SSH、不依赖任何中心服务器。

- **一个静态程序**：C99，二三百 KB，没有运行时依赖。密码学只用 [Monocypher](https://monocypher.org)。
- **不依赖 SSH**：shell（POSIX 伪终端 / Windows ConPTY）和端口转发都是自己的服务，跑在端到端加密的流上。
- **去中心化**：身份是节点公钥；成员名单由主钥匙签名、在节点之间互传；只有节点，没有特殊角色——从外面连得进来的节点（过了观察期，能用 UPnP 时自动在路由器上开端口）顺带帮别人转发、用 HTTP 给还没装的机器发安装包。
- **特权只认主钥匙**：没有特权机器。批准新机器、签通行证、发版都要主钥匙签名；主钥匙只在 ssh-agent 里，由 12 个词的口令派生。
- **默认拒绝**：没有有效通行证，名单里的成员之间也不能开 shell 或端口。
- **自升级**：每台机器自己从 GitHub Release 拉签名清单；网内已有新版的节点就先从网内取，取不到再去 GitHub。每台机器只留最新版，缓存它的全部发布物（各平台程序、接入脚本、源码），旧版本自动删掉。换上后试用，连不上网络就自动回滚。

## 接入一台机器

**Linux / OpenWrt / macOS**

```sh
curl -fsSL https://github.com/<owner>/<repo>/releases/latest/download/custhub3-join.sh | sh
```

**Windows 10 / 11**（用管理员身份打开 PowerShell）

```powershell
irm https://github.com/<owner>/<repo>/releases/latest/download/custhub3-join.ps1 | iex
```

**从网里的机器下载（Windows 7 起 / Mac / Linux 通用，一行）**：网里已经有机器时，管理员跑 `custhub line`（或界面里按 `n`）得到一行命令，地址是网里一台从外面连得进来的机器的 `http://IP:端口`：

```
powershell -c "start powershell -verb runas -args '-NoExit -c iex(New-Object Net.WebClient).DownloadString(''http://IP:8444/ps1'')'"; curl -fsSL http://IP:8444/sh|sh
```

Windows 在 Win+R / cmd / PowerShell 里粘贴运行（弹 UAC），Mac / Linux 在终端里粘贴运行。每台机器都缓存最新版的全部发布物（各平台程序、接入脚本、源码，清单由主钥匙签名），监听口上有一个只读 HTTP 照 GitHub Release 的路径发出去，所以 Win7 这种连不了 GitHub HTTPS 的机器也能装。普通 HTTP 不防半路调包：接入脚本按清单核对程序的 sha512，但脚本本身没有校验。

它会下载本平台的程序（GitHub 连不上时自动走镜像），按发布清单核对 sha512，装进系统目录、注册成系统服务，然后向网里报到并显示**接入码**（形如 `R44-CQP`）。把接入码告诉管理员，批准后屏幕上显示"已接入"。装好后 `custhub` 命令已经在 PATH 里（Linux / macOS：`/usr/local/bin/custhub`，OpenWrt：`/usr/bin/custhub`，用户模式：`~/.local/bin`；Windows：安装目录加进系统 PATH）。跑接入的那个账号（用 sudo 时是 sudo 之前的账号）会加进本机的 `custhub` 用户组，重新登录后不用 sudo 就能 `custhub sh / connect / ls / pass`；别的账号用 `sudo custhub user add <账号>` 加（`user del` 移出，`user ls` 列出）。组里的账号经本机守护办事，碰不到节点钥匙；但能用本机的通行证开别的机器的 shell，只加可信的人。`join`、`remove`、`user`、`key` 要 root，不是 root 时自动换成 `sudo`（Windows 上提示用管理员终端）。

### 工程师登录

1. 工程师电脑照上面接入（自己的 Mac 建议用户模式：`curl … | CUSTHUB_JOIN_ARGS=--user sh`），把接入码给管理员。
2. 管理员：`custhub key approve <接入码> zhang`，再 `custhub key pass --for zhang --to web1,web2 --hours 8`，得到 `zhang.pass`，发给工程师。
3. 工程师：`custhub pass zhang.pass`，然后 `custhub sh web1`。`custhub pass` 不带参数列出本机的通行证和剩余时间。

## 终端界面

直接敲 `custhub`（不带参数）进界面：机器列表（在线没有、版本、直连还是经哪台转），选中按 Enter 开 shell，`v` 看本机通行证，`i` 装别人发来的通行证。按 `u` 解锁主钥匙后多出管理功能：待批准（`a` 批准，默认用对方机器名）、`s` 签通行证、`n` 新客户接入（一行通用接入命令，Windows / Mac / Linux 都能直接粘贴）、`d` 移出名单、`l` 上锁。

## 管理员

管理员自己的电脑用**用户模式**装（装在 `~/.custhub`，用自己账号的登录项跑，不要 root）：

```sh
custhub join --user --github <owner>/<repo>
```

```sh
custhub key unlock                      # 输入 12 个词, 主钥匙进 ssh-agent(默认 8 小时)
custhub key pending                     # 待批准的机器, 带接入码
custhub key approve R44-CQP             # 按接入码批准: 自动编号 A-1、A-2 …(对方机器名记进备注)
custhub key approve R44-CQP office-pc   # 或者自己起名
custhub key rename A-3 office-pc        # 改名(编号不会再分给别人)
custhub key pass --to office-pc --svc "sh port:3389" --hours 2   # 给本机签通行证(--svc 默认 sh)
custhub sh office-pc                    # 交互 shell
custhub sh office-pc -- ipconfig        # 跑一条命令, 退出码原样带回
custhub connect office-pc 3389          # 标准输入输出接到对方本机端口(或给 ssh 当 ProxyCommand)
custhub key remove office-pc            # 移出名单
custhub key lock
```

本机还有 sshd 的，也可以把 22 当普通端口：`ssh -o ProxyCommand="custhub connect %h 22" 名字`。

### 第一次建网

1. `custhub key unlock`：还没有节点时会打印由口令推出的主公钥。
2. 在每台准备当种子的机器（有公网地址的服务器）上 `custhub keygen /opt/custhub/node`，记下公钥；管理电脑上 `custhub keygen ~/.custhub/node`。
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
4. 发版（`dist/release.sh <owner>/<repo>`，见下），然后各种子机器、管理电脑照常接入（种子机器要在防火墙 / 安全组放行 TCP 8444）。

名单里带地址只在第一次建网时用（那时还没有任何节点知道谁可达；老写法 `relay <名字> <公钥> <地址>` 照样认）。之后名单只管谁是成员：以后每次改名单（批准、改名、移出）都会顺手去掉这些地址。

谁可达由各台机器自己决定：回连自检通过、过了观察期（默认 5 分钟，期间每分钟回连测一次，中途不通就从头算），就在位置记录里声明。每台机器把见过的可达地址记进地址簿（节点目录下的 `peers`）。重启后靠地址簿找人；上次就可达的机器重启后免观察期；观察期中重启（比如升级），已观察的时长接着算（节点目录下的 `obs`）。节点发种子（`custhub key seed`、节点 HTTP 的 `custhub3.seed`）时附上地址簿里的可达地址（`hint <公钥> <地址>` 行，本机排在最前），新机器接入后记进自己的地址簿。地址错了不要紧，握手时会核对公钥。一台机器谁都连不上超过 1 分钟（比如离线很久、地址簿全过时）时，会自己去发布源取 `custhub3.seed`，读里面的可达地址和更新的名单。

**多端点直连**：监听所有地址的机器，会把自己各个局域网 IPv4 地址加监听端口写进位置记录（`端点=`）。别的机器把对方报的端点和公网地址一起轮流试，通了就留下；只要一边报了端点就能连上。规则对所有机器都一样，同一局域网的机器自然走局域网直连，不用绕可达节点。只有局域网端点、对方又不可达时，重试间隔放长到 1 分钟。经局域网地址连着的链路不用来做回连测试，因为测出来的是局域网地址，不算数。

**打洞**：两台都连不进来、又不在同一局域网时，用 TCP 同时打开直接连上；打不通就照旧经可达节点中转。
- **查映射（STUN）**：不可达的机器固定用一个打洞端口（监听端口 + 10），从它去问可达节点的 `/whoami`，得到这个端口在公网上被映射成什么。问两台不同的可达节点，映射一样才算可用，写进位置记录（`打洞=`）。两次映射不一样是对称型 NAT，不报。
- **交换端点（DISCO）**：打洞端点随位置记录在网里传开，不另发消息。
- **同时拨**：双方都有打洞端点、又还没有直连时，在同一个时间窗里（每 15 秒里的前 6 秒，各按各的钟）每秒从打洞端口拨对方的打洞端点。两边的握手包在路上交错时，双方 NAT 都已经开了口，就合成一条 TCP。公钥小的一方当 Noise 发起方。

**UDP 链路（热备）**：每台在 TCP 监听的同一个端口号上开一个 UDP 端口，和每个在线成员都挂一条 UDP 链路。平时流量走 TCP（IPv6 优先于 IPv4），TCP 断了新流量马上落到 UDP，不用重新拨号。对方的 UDP 地址轮流试三种：局域网端点、可达地址、UDP 打洞端点。双方都可以拨，重复的按公钥规则只留一条；拨不通的退避，最长 5 分钟。不可达的机器向可达节点的 UDP 端口查映射（发 `W`，回 `w` 加地址），两次映射一致才写进位置记录（`UDP打洞=`）。打洞的时间窗里先互发招呼包（`P`），再开 KCP 会话（`K`）。会话里跑的就是 TCP 链路那套 Noise 握手和帧，只是字节流换成 KCP（`vendor/ikcp.c`，MIT；流模式，MTU 1200，节拍 20ms）。UPnP 会把同一个外部端口的 UDP 也映射上；Linux / OpenWrt 防火墙同时放行 UDP。界面的连接栏写明协议，比如 `直连 TCP+UDP`。

**选路、诊断、网络变化**：
- **按延迟选路**：每条直连都用带时间戳的心跳测来回延迟（有流量时也每 5 秒测一次）。新连接挑最近 30 秒里最低延迟的那条，偏好顺序是 IPv6 > IPv4 > UDP：IPv4 要比 IPv6 快 20ms 以上才换，UDP 要比 TCP 快 5ms 以上才换。
- **`custhub ping <名字>`**：列出到那台的各条直连（TCP IPv4 / IPv6、UDP）和延迟，标出正在走的那条；没有直连时显示经谁中转。每秒刷新一次，共 4 次。
- **`custhub netcheck`**：本机网络状况，包括地址、IPv4 入站、UPnP、IPv6、TCP 和 UDP 的打洞映射（能不能打洞、是不是对称型 NAT），以及到每台的直连和延迟。
- **UPnP 自修**：路由器说映射着，回连测试却不通时（比如路由器防火墙重载，把 miniupnpd 的转发规则清了，登记还在），删掉这条映射再重新申请，逼路由器重新装上转发规则。最多 5 分钟做一次。
- **网络变化马上重连**：每 2 秒看一次本机地址（换 Wi-Fi、光猫重启、插拔网线都会变）。一变就马上重查映射、UPnP、回连测试，重新拨号、重新挂 UDP；各条链路立刻发心跳，3 秒内没回音的关掉，不再等 9 秒超时。

**双栈热备**：本机有公网 IPv6 时，同时监听 IPv4 和 IPv6，两种地址分开做回连自检、分开过观察期、分开算可达，任一可达就算可达节点。路由器或光猫的 IPv6 防火墙常会挡入站连接，这种情况下 IPv6 不可达，但照样能主动连出去。声明的是网卡上的固定 IPv6 地址，不用每天会换的临时地址。Windows 上程序启动时会在防火墙里放行自己（规则名 custhub，按程序放行，IPv4、IPv6 都管）。对方两种都可达时，两条链路同时挂着：新流量优先走 IPv6，IPv6 断了马上落到 IPv4，不用重新拨号；IPv6 恢复后新流量再回到 IPv6。断线时正在跑的连接要重连一次。位置记录、地址簿、种子里的 IPv6 地址写成 `[地址]:端口`。conf 可用 `listen6` / `announce6` 指定（同 `listen` / `announce`）。

## 安全模型

- 链路：TCP + Noise IK（X25519 / ChaCha20-Poly1305 / BLAKE2b），只收名单里的公钥。经别的节点转发的流里再套一层端到端 Noise：转发的节点只看得到谁连谁。
- 名单、发布清单、通行证、种子都用主钥匙以 `ssh-keygen -Y sign` 的格式签名（ssh-keygen 也能验）。
- 通行证绑定发起方节点公钥，写明能进哪些机器、能用哪些服务、有效期（默认 2 小时、最长 1 天），对方自己验，不问任何中心。名单外的机器持证也能挂进网里当访客，只能连通行证里写的机器。
- 本机：节点钥匙、通行证、日志只给 root / 管理员；`custhub` 组只能读 conf 和控制口令牌（POSIX：节点目录 0710、这两个文件 0640 root:custhub；Windows：本地组 custhub 只对这两个文件可读）。本机控制口要出示每次启动随机生成的令牌。
- 主钥匙：12 个词 → scrypt(N=2^17, r=8, p=1) → ed25519；私钥不落盘，只在 ssh-agent 里。

## 平台

| | 服务 | shell |
|---|---|---|
| Linux（x86_64 / arm64 / armv5 / mips / mipsel，静态 musl） | systemd | 伪终端 |
| OpenWrt | procd | 伪终端 |
| macOS（arm64 / x86_64） | launchd | 伪终端 |
| Windows 10 1809 及以上（x64 / x86） | 计划任务（SYSTEM） | 交互用 ConPTY，跑命令用管道 |
| Windows 7 / 8 / 8.1（x64 / x86，补丁模块 `plat_win7.c`，链 msvcrt） | 计划任务（SYSTEM） | 管道 + 守护这边做行编辑回显（没有 ConPTY）；没有终端界面 |

## 编译与测试

```sh
./build.sh              # 本机编一份 ./mesh(就是 custhub, 测试用)
./build.sh release      # 交叉编译全部发布目标(要 zig) → dist/out/
dist/release.sh <owner>/<repo> [--dry]   # 编、签发布清单和种子(主钥匙要已解锁)、gh release create
```

| 测试 | 内容 |
|---|---|
| `purity.sh` | 核心文件里没有条件编译、只用 C99 标准头文件（系统差异只在 `plat_posix.c` / `plat_win.c`） |
| `pass-test.sh` | 通行证：验与签 |
| `test.sh` | 两台可达节点 + NAT 后节点 + 访客：连通、大流量、转发方读不到内容、换节点、换地址、兜底、拒绝 |
| `role-test.sh` | 可达自检、观察期、报到 / 批准 |
| `lan-test.sh` | 多端点: 不可达的两台靠各自报的局域网端点直接连上 |
| `punch-test.sh` | 打洞: STUN 查映射、端点随位置记录传开、两台不可达的同时拨直连(要 iptables, 测试时丢 RST 模拟 NAT) |
| `udp-test.sh` | UDP 链路: 查映射、UDP 打洞、KCP 上跑握手和帧; 丢 20% 的包 1MB 原样到达(lan / punch 测试另查 TCP+UDP 热备) |
| `net-test.sh` | 心跳测延迟、`custhub ping` / `netcheck`、网络变化马上重查重连 |
| `v6-test.sh` | 双栈: IPv4、IPv6 分开算可达; 两条链路热备, 优先 IPv6, 断了马上走 IPv4 |
| `sh-test.sh` | shell：命令、退出码、大输出、交互、窗口大小、Ctrl-C、收尾 |
| `upnp-test.sh` | UPnP 自动映射（假路由器） |
| `rel-test.sh` | 发布物：GitHub、网内取包、每台缓存全部发布物、只读 HTTP、只留最新版、灰度、坏 sha512、回滚 |
| `join-test.sh` | 接入（演练模式，不碰系统）、用户模式、权限、控制口令牌、卸载 |
| `admin-test.sh` | 管理端：解锁（和参考实现对照）、批准、移除、种子、发布清单、第一次建网 |
| `dist-test.sh [win主机 本机地址]` | 一行命令的引导脚本 |
| `linux-test.sh` | 以上在 Debian 容器里用 gcc 再跑一遍 |
| `win-test.sh` / `win-cross-test.sh` / `win-install-test.sh` / `posix-install-test.sh` | 实机：Windows 平台模块、跨机器、真装 → 升级 → 卸载 |

## 代码分层

| 层 | 文件 |
|---|---|
| 服务（shell / 端口 / 取包） | `svc.c` `sh.c` `rel.c` |
| 通行证 | `pass.c` |
| 连通（链路、转发、找人、自检、UPnP、控制口） | `link.c` `hop.c` `disc.c` `qual.c` `upnp.c` `app.c` |
| 身份（握手、签名、口令派生） | `noise.c` `sig.c` `sshsig.c` `kdf.c` |
| 部署 / 管理端 | `join.c` `key.c` |
| 平台模块（编译时选一个） | `plat_posix.c` / `plat_win.c` + 版本模块 `plat_win10.c` 或 `plat_win7.c`，接口 `plat.h` |

## 许可证

GPL-3.0。`vendor/` 里的 Monocypher 是 CC0-1.0 / BSD-2-Clause 双许可（见 `vendor/LICENCE.md`）；KCP（`vendor/ikcp.c`，1.7 版）是 MIT 许可（见 `vendor/LICENSE-kcp`）。
