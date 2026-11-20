#!/usr/bin/env bash
# 打洞(本机多进程): x、y 都连不进来(观察期很长)、没有局域网端点(只听 127.0.0.1), 原来只能经 r 中转
#   STUN: 从打洞端口(监听端口 + 10)问 r 的 /whoami 得到映射, 写进位置记录(打洞=)
#   同时拨: 双方在同一时间窗里从打洞端口互拨, 合成一条 TCP; 公钥小的当 Noise 发起方
#   回环上没人听的端口会立刻回 RST, 真 NAT 是悄悄丢掉; 测试期间丢掉两个打洞端口发出的 RST 来模拟(要 iptables + NET_ADMIN, 没有就跳过)
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
base=$((20000 + RANDOM % 20000)); PR=$base PX=$((base+1)) PY=$((base+2)) ECHO=$((base+3)) QX=$((base+11)) QY=$((base+12))
rules(){ for p in $QX $QY; do iptables "$1" OUTPUT -o lo -p tcp --sport $p --tcp-flags RST RST -j DROP 2>/dev/null || return 1; done; }
command -v iptables >/dev/null && rules -I || { echo "  (没有 iptables 或没权限, 跳过)"; echo "== 结果: 通过 0, 失败 0"; exit 0; }
T=$(mktemp -d); trap 'rules -D; kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
export CUSTHUB_MESH_OBS_S=3600 CUSTHUB_IP6=

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r x y; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "node r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node x $(cat "$T/x.pub")"; echo "node y $(cat "$T/y.pub")"; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d"; cat "$T/d" "$T/d.sig" >"$T/t1"
i=0; for n in r x y; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nallow %s\nlog %s\nupnp off\n' "$(cat "$T/master.pub")" $((base+20+i)) "$ECHO" "$T/$n.log" >"$T/$n/conf"
  cp "$T/t1" "$T/$n/trust"
done
echo "listen 127.0.0.1:$PR" >>"$T/r/conf"; echo "listen 127.0.0.1:$PX" >>"$T/x/conf"; echo "listen 127.0.0.1:$PY" >>"$T/y/conf"
python3 - "$ECHO" <<'EOF' >/dev/null 2>&1 &
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(8)
def h(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
EOF
. ./testlib.sh
mkpass "$T/master" "$T/x/pass" "$(cat "$T/x.pub")" all "port:*"
for n in r x y; do $M run "$T/$n" & done
punched(){ $M ls "$T/x" | sed -n '/^链路/,/^位置/p' | grep -qE "^  y +打洞 127.0.0.1:$QY"; }

echo "== 1 STUN: 问可达节点 /whoami, 打洞端点写进位置记录"
ok "/whoami 回请求方的地址:端口" '[ "$(curl -s --local-port $((base+30)) http://127.0.0.1:$PR/whoami)" = "127.0.0.1:$((base+30))" ]'
wait_for 20 grep -q "打洞=127.0.0.1:$QY" <($M ls "$T/x")
ok "x 收到 y 的打洞端点 127.0.0.1:$QY" '$M ls "$T/x" | grep -q "^  y .*打洞=127.0.0.1:$QY"'
ok "x 的 ls 有打洞一行" '$M ls "$T/x" | grep -q "^打洞: 127.0.0.1:$QX$"'
ok "可达的 r 不报打洞端点" '! $M ls "$T/x" | grep -q "^  r .*打洞="'

echo "== 2 同时拨: 不可达的两台打洞直连"
wait_for 40 punched
ok "x 和 y 之间有打洞的链路" 'punched'
ok "x 连 y 的服务直接走, 不经 r" '[ "$(printf hi | $M connect "$T/x" y $ECHO 2>/dev/null)" = hi ] && grep -q "已连上 y port:$ECHO(经 y)" "$T/x.log"'
ok "两边都只留一条打洞链路(公钥小的当发起方, 没有重复)" '[ "$($M ls "$T/x" | sed -n "/^链路/,/^位置/p" | grep -c "^  y ")" = 1 ] && [ "$($M ls "$T/y" | sed -n "/^链路/,/^位置/p" | grep -c "^  x ")" = 1 ]'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 20 "$T"/*.log; }
[ $fail -eq 0 ]
