---
name: custhub
description: 用 custhub 操作远程机器(查机器信息、多台跑命令、传文件、查网络、测速)。触发: custhub / 远程机器 / 客户机 / 在 A-2 上跑 / 传文件到某台 / 看看哪些机器在线 / 批量执行。
---
# custhub 给 AI 的用法

custhub 是一张去中心化的远程维护网络。每台机器有个名字(如 `A-2`), 本机跑着守护进程, 命令都问本机守护, 不用 SSH。

## 规矩(先看)
- **在别人的机器上执行、传文件、测速之前, 先问人同意**(说清楚哪几台、做什么)。只读本机守护的命令(`inventory` `ls` `netcheck` `ping`)不用问。
- 权限靠通行证。主钥匙解锁着时本机会自动给自己签(0.3.51 起), 所以被拒(`没有通行证` / `通行证…`)一般 = 主钥匙锁着。**不要自己解锁主钥匙或签证**, 告诉人「解锁一下」或缺哪台、什么服务, 由人签:
  `custhub key pass --to A-2,A-7 --svc sh --hours 1`(人执行; 要先 `custhub key unlock`)。
- 不要往 `custhub sh` 里灌按键再抠终端输出: 用 `exec`。

## 第一步: 看全局(一次调用)
```
custhub inventory --json
```
每台一条: `name self online version platform host os model capability addr addr6 last_seen_s link`。
- `capability`: `dualstack` / `public`(能被连进来) / `ipv6` / `p2p`(能打洞) / `relay`(只能中转)
- `link`: 本机到它现在怎么连 `{kind: tcp4|tcp6|udp, addr, rtt_ms}`, 或 `{kind: relay, via}`, 或 `null`(不通)
- `platform` 以 `win7-` 开头的是 Win7, `win-` 是 Win10/11, `linux-`、`mac-`
- `features`: 它支持的功能(`file` 传文件、`bench` 测速、`info` 远程查看…); 没有的就别对它用, 会直接报「对方还不支持」

## 跑命令(一台或多台, 并行)
```
custhub exec <目标> [--json] [--timeout 秒] -- 命令…
```
- 目标: `A-2` / `A-2,A-7` / 分组 `@all` `@online` `@win` `@win7` `@linux` `@android` `@mac`(都不含本机, 能混用: `@win7,A-3`)
- `--json`: 每台 `{name, ok, code, ms, truncated, output, error}`; `error` 非空 = 没跑成(不在线、没权限、超时)
- 不加 `--json` 时输出一样的机器合成一组显示, 一眼看出哪台不一样
- 全部退出码 0 才返回 0; 用法错返回 2
- **Windows 上命令交给 `cmd.exe /c`(代码页已切 UTF-8, 中文正常)**: 用 cmd 语法; 要 PowerShell 就写 `powershell -NoProfile -Command "…"`
- 输出是伪终端里的: 标准输出和错误输出合在一起, 已去掉颜色和控制码; 每台最多收 1MB
- 默认超时 60 秒; 长任务加 `--timeout`

## 传文件
```
custhub send <本机文件> <名字> <对方路径>     # 对方路径是目录(或以 / \ 结尾)就放进去、同名
custhub pull <本机路径> <名字> <对方文件>     # 本机路径是目录就放进去
```
一次一个文件; 断了再执行同一条命令会续传; 传完核对哈希, 对不上不留文件; 中文和空格路径都行。要 `file` 或 `sh` 通行证。
加 `--json`: 只在最后打一行 `{op, ok, name, path, bytes, resumed_from, ms, error}`, 不刷进度。

## 网络和诊断(只读本机, 不用问)
- `custhub ping <名字> [--json]`: 到它的每条直连(TCP IPv4/IPv6、UDP)和延迟, 走哪条
- `custhub netcheck [--json]`: 本机能不能被连进来、UPnP、IPv6、打洞、到各台的延迟
- `custhub log [--grep 关键字] [--lines N]`: 本机日志
- `custhub ls`: 守护的原始状态(人看的)
- `custhub bench <名字> [秒] [--json]`: 测上传 / 下载速度(会占对方带宽, **先问人**; 要 `sh` 通行证)

## 看别的机器(只读, 要 info 或 sh 通行证; 也算连别人的机器, 先问人)
- `custhub netcheck <名字> [--json]`: 它的网络状况
- `custhub log <名字> [--grep 关键字] [--lines N]`: 它的日志(只要含关键字的最后几行)

## 等待和事件(不用自己写轮询)
- `custhub wait <名字> online|offline|reachable|direct|version <版本> [--timeout 秒]`: 条件成立返回 0, 超时返回 4
  例: 发版后 `custhub wait A-2 version 0.3.48 --timeout 600`
- `custhub watch --json`: 持续输出事件, 每行 `{id, time, name, type, from, to}`;
  type: `online` `offline` `offline_long`(离线满 10 分钟) `version` `capability` `link`(direct/relay/none) `behind`(版本落后满 30 分钟)
- `custhub alerts on|off|status`: 这台电脑、当前用户登录时自动后台看着, 有问题弹系统通知(改的是人的电脑配置, **先问人**)

## 常见情况
- `exec` 某台 `✘ 名单里没有…` / 分组不认识: 用 `inventory` 看名字
- 某台 `online:false`: 不在线, 别重试; 告诉人
- 刚发版后有的机器版本落后: 正常, 它们会自己升级; `inventory` 看 `version`
