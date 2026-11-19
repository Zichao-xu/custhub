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

名单里带地址的那几行只是**种子线索**（冷启动时去哪里找人；老写法 `relay <名字> <公钥> <地址>` 照样认）；它们和别的节点一样要通过回连自检才算可达。

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

GPL-3.0。`vendor/` 里的 Monocypher 是 CC0-1.0 / BSD-2-Clause 双许可（见 `vendor/LICENCE.md`）。
