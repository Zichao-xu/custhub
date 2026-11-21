#!/usr/bin/env bash
# 接入验收(design-v3 §0 第 17 条): 演练模式(CUSTHUB_SVC_DRY=1: 服务文件写到 安装目录/node/dry/, 不碰系统, 守护直接在后台起)
#   1 join: 种子验签 → 装程序 → 节点钥匙 → conf → 服务文件 → 报到, 屏幕显示接入码, 等批准
#   2 管理员把它加进名单(这里直接签名单交给可达节点) → join 显示已接入
#   3 三种服务文件(systemd / procd / launchd)的内容
#   4 重复执行: 钥匙不变, 已在名单里不用再批准
#   5 remove: 停服务、删安装目录
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; [ -f "$T/home/node/dry/pid" ] && kill $(cat "$T/home/node/dry/pid") 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}; PR=$base
CP=$((base+20)); export CUSTHUB_HOME=$T/home CUSTHUB_SVC_DRY=1 CUSTHUB_MESH_PENDING_S=2 CUSTHUB_CTL=127.0.0.1:$CP CP   # 控制口避开本机真在跑的 7481
ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
mkdir -p "$T/r"; $M keygen "$T/r" >"$T/r.pub"
sign(){ local v=$1; shift; { echo "custhub-mesh-trust $v"; printf '%s\n' "$@"; echo "--end--"; } >"$T/data"; rm -f "$T/data.sig"
  ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/data" 2>/dev/null; cat "$T/data" "$T/data.sig"; }
sign 1 "relay r $(cat "$T/r.pub") 127.0.0.1:$PR" >"$T/t1"
{ echo "custhub-seed v1"; echo "master $(cat "$T/master.pub")"; echo "github example/custhub"; echo "--trust--"; cat "$T/t1"; } >"$T/seed"
printf 'master %s\nctl 127.0.0.1:%s\nlog %s/r.log\nupnp off\n' "$(cat "$T/master.pub")" $((base+11)) "$T" >"$T/r/conf"; cp "$T/t1" "$T/r/trust"
$M run "$T/r" 2>/dev/null &
mkdir -p "$T/home/node"; printf 'upnp off\nrelay off\n' >"$T/home/node/conf"     # 本机手动加过的: join 要保留

echo "== 1 join"
CUSTHUB_SVC_KIND=systemd $M join --seed "$T/seed" --wait 40 >"$T/join.out" 2>&1 &
JP=$!
wait_for 15 grep -q "接入码" "$T/join.out"
code=$(sed -n 's/^  接入码: \([0-9A-Z]\{3\}-[0-9A-Z]\{3\}\)$/\1/p' "$T/join.out")
[ -n "$code" ] && [ "$code" = "$($M code "$T/home/node")" ] && ok "显示接入码 $code(和节点公钥算出来的一致)" || ng "接入码: [$code] $(cat "$T/join.out")"
[ -x "$T/home/custhub" ] && cmp -s "$M" "$T/home/custhub" && ok "程序装进安装目录" || ng "安装目录里没有程序"
grep -q "^github example/custhub$" "$T/home/node/conf" && grep -q "^ctl 127.0.0.1:$CP$" "$T/home/node/conf" && grep -q "^upnp off$" "$T/home/node/conf" && grep -q "^relay off$" "$T/home/node/conf" && ok "conf: 种子里的仓库、控制口, 本机手动加的 upnp / relay 留着" || ng "conf: $(cat "$T/home/node/conf")"
grep -qF "ExecStart=\"$T/home/custhub\" run \"$T/home/node\"" "$T/home/node/dry/custhub.service" && grep -q "^Restart=always" "$T/home/node/dry/custhub.service" && ok "systemd 服务文件: 跑 custhub run, 挂了自动拉起" || ng "systemd: $(cat "$T/home/node/dry/custhub.service" 2>&1)"
NP=$($M pub "$T/home/node")
wait_for 15 grep -qF "$NP" "$T/r/pending"
grep -qF "$NP" "$T/r/pending" && ok "节点向可达节点报到, 进了待批准" || ng "可达节点的待批准里没有它"

echo "== 2 批准"
sign 2 "relay r $(cat "$T/r.pub") 127.0.0.1:$PR" "node n1 $NP" >"$T/t2"
$M ctl "$T/r" "TRUSTPUT $(base64 <"$T/t2" | tr -d '\n')" >/dev/null
wait $JP; c=$?
grep -q "^已接入: 名字 n1$" "$T/join.out" && [ $c = 0 ] && ok "join 显示已接入: 名字 n1" || ng "join 输出: $(tail -3 "$T/join.out") 退出码 $c"

echo "== 3 其他服务管理方式"
for k in procd launchd; do CUSTHUB_SVC_KIND=$k $M join --seed "$T/seed" --wait 1 >/dev/null 2>&1; done
grep -qF "procd_set_param command \"$T/home/custhub\" run \"$T/home/node\"" "$T/home/node/dry/custhub" && grep -q "procd_set_param respawn" "$T/home/node/dry/custhub" && ok "procd(OpenWrt): 带 respawn" || ng "procd: $(cat "$T/home/node/dry/custhub" 2>&1)"
grep -qF "<string>$T/home/custhub</string><string>run</string><string>$T/home/node</string>" "$T/home/node/dry/com.custhub.run.plist" && grep -q "<key>KeepAlive</key><true/>" "$T/home/node/dry/com.custhub.run.plist" && ok "launchd(Mac): KeepAlive" || ng "launchd: $(cat "$T/home/node/dry/com.custhub.run.plist" 2>&1)"

echo "== 3b 用户模式(管理电脑)"
CUSTHUB_SVC_KIND=launchd-user $M join --user --seed "$T/seed" --wait 1 >/dev/null 2>&1
grep -qF "<string>$T/home/custhub</string><string>run</string><string>$T/home/node</string>" "$T/home/node/dry/com.custhub.run.plist" && ok "join --user: 用自己账号的 LaunchAgent(不要 root)" || ng "用户模式: $(ls "$T/home/node/dry")"
mode(){ stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }   # GNU / BSD
[ "$(mode "$T/home/node")" = 700 ] && [ "$(mode "$T/home/node/node.key")" = 600 ] && ok "节点目录 0700、钥匙 0600" || ng "权限: $(ls -ld "$T/home/node" "$T/home/node/node.key")"
[ "$(mode "$T/home/node/ctl.token")" = 600 ] && ok "控制口令牌 0600" || ng "令牌权限: $(ls -l "$T/home/node/ctl.token" 2>&1)"
o=$(python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",int(__import__("os").environ["CP"])),3); s.sendall(b"LS\n"); print(s.recv(200).decode().strip())' 2>&1); echo "$o" | grep -q "令牌不对" && ok "不带令牌连控制口被拒: $o" || ng "控制口没令牌: [$o]"

echo "== 4 重复执行"
CUSTHUB_SVC_KIND=systemd $M join --seed "$T/seed" --wait 15 >"$T/join2.out" 2>&1
[ "$($M pub "$T/home/node")" = "$NP" ] && ok "节点钥匙不变" || ng "钥匙变了"
grep -q "本机已在名单里(n1)" "$T/join2.out" && grep -q "^已接入: 名字 n1$" "$T/join2.out" && ok "已在名单里: 不用再批准, 直接已接入" || ng "再次 join: $(cat "$T/join2.out")"

o=$($M run "$T/home/node" 2>&1); c=$?
[ $c = 0 ] && grep -q "本机已经有一份在跑" "$T/home/node/mesh.log" && kill -0 "$(cat "$T/home/node/dry/pid")" 2>/dev/null && ok "服务管理器多拉起一份: 控制口占着, 这份退出(退出码 0), 原来那份照跑" || ng "第二份: 退出码 $c $(tail -2 "$T/home/node/mesh.log")"

echo "== 4b 命令进 PATH(链接放到 CUSTHUB_PATH_DIR, 不碰系统)"
CUSTHUB_PATH_DIR=$T/bin CUSTHUB_SVC_KIND=systemd $M join --seed "$T/seed" --wait 5 >"$T/join3.out" 2>&1
[ "$(readlink "$T/bin/custhub")" = "$T/home/custhub" ] && "$T/bin/custhub" version | grep -q "^custhub " && grep -q "命令: custhub → $T/bin/custhub" "$T/join3.out" && ok "join 后 custhub 在 PATH 目录里(链到安装目录那份), 能直接跑" || ng "PATH: $(ls -l "$T/bin" 2>&1); $(grep 命令 "$T/join3.out")"
o=$("$T/bin/custhub" help); echo "$o" | grep -q "custhub sh <机器>" && ! echo "$o" | grep -q "<目录>" && ok "help: 不用写目录" || ng "help: $o"

echo "== 5 remove"
pid=$(cat "$T/home/node/dry/pid")
CUSTHUB_PATH_DIR=$T/bin $M remove >"$T/rm.out" 2>&1
[ ! -e "$T/bin/custhub" ] && ok "remove 撤掉了 PATH 里的链接" || ng "链接还在"
sleep 1
! kill -0 "$pid" 2>/dev/null && ok "服务停了" || ng "守护还在"
[ ! -e "$T/home" ] && ok "安装目录删了" || ng "安装目录还在: $(ls "$T/home" 2>&1)"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
