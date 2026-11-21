#!/usr/bin/env bash
# 多端点直连(本机多进程, 局域网地址是容器自己的 IPv4): 每台把自己的局域网地址(本机各局域网 IPv4 + 监听端口)报进位置记录; 别人把对方报的端点都试一遍, 通的留下
#   r: 可达节点(127.0.0.1), x、y: 监听所有地址、观察期很长(不算可达), 原来只能经 r 中转; 现在靠各自报的局域网端点直接连上
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}; PR=$base PX=$((base+1)) PY=$((base+2)) ECHO=$((base+3))
export CUSTHUB_MESH_OBS_S=3600 CUSTHUB_IP6=
LAN=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -E '^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.' | head -1)
[ -n "$LAN" ] || { echo "  (本机没有局域网 IPv4, 跳过)"; echo "== 结果: 通过 0, 失败 0"; exit 0; }

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r x y; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "node r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node x $(cat "$T/x.pub")"; echo "node y $(cat "$T/y.pub")"; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d"; cat "$T/d" "$T/d.sig" >"$T/t1"
i=0; for n in r x y; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nallow %s\nlog %s\nupnp off\n' "$(cat "$T/master.pub")" $((base+10+i)) "$ECHO" "$T/$n.log" >"$T/$n/conf"
  cp "$T/t1" "$T/$n/trust"
done
echo "listen 127.0.0.1:$PR" >>"$T/r/conf"; echo "listen 0.0.0.0:$PX" >>"$T/x/conf"; echo "listen 0.0.0.0:$PY" >>"$T/y/conf"
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
lan_link(){ $M ls "$T/x" | sed -n '/^链路/,/^位置/p' | grep -qE "^  y +(出站|入站) $LAN:"; }

echo "== 1 报端点"
wait_for 30 grep -q "端点=$LAN:$PY" <($M ls "$T/r")
ok "y 的位置记录带局域网端点 $LAN:$PY" '$M ls "$T/r" | grep -q "^  y .*端点=$LAN:$PY"'
ok "r 只听 127.0.0.1, 不报端点" '! $M ls "$T/x" | grep -q "^  r .*端点="'
ok "x、y 都不算可达(观察期很长)" '$M ls "$T/x" | grep -q "^  y *节点" && ! grep -q "可达: 对外" "$T/x.log"'

echo "== 2 不可达的两台靠端点直接连上"
wait_for 20 lan_link
ok "x 和 y 之间有直接的链路(局域网地址)" 'lan_link'
ok "x 连 y 的服务直接走, 不经 r" '[ "$(printf hi | $M connect "$T/x" y $ECHO 2>/dev/null)" = hi ] && grep -q "已连上 y port:$ECHO(经 y)" "$T/x.log"'
ok "同时还挂着一条 UDP(热备, 走局域网端点)" 'wait_for 30 sh -c "$M ls $T/x | sed -n \"/^链路/,/^位置/p\" | grep -q \"^  y  *UDP $LAN:\""'
ok "经局域网连着的不替对方做回连测试(测出来是局域网地址)" '! grep -q "端口: 已开启: $LAN" "$T/x.log" "$T/y.log"'

echo "== 3 只有一边报端点也够: y 不再报, 由 y 去连 x 报的端点"
kill $(pgrep -f "$M run $T/y") 2>/dev/null; sleep 1
sed -i "s/^listen 0.0.0.0:$PY/listen 127.0.0.1:$PY/" "$T/y/conf"; : >"$T/y.log"
$M run "$T/y" &
wait_for 20 grep -q "链路建立 r" "$T/y.log"
ok "y 只听 127.0.0.1 后不再报端点" 'wait_for 30 sh -c "! $M ls $T/x | grep -q \"^  y .*端点=\""'
wait_for 20 grep -q "链路建立 x(出站, $LAN:$PX)" "$T/y.log"
ok "y 主动连上 x 的局域网端点, x 连 y 的服务照样直接走" '[ "$(printf hi2 | $M connect "$T/x" y $ECHO 2>/dev/null)" = hi2 ] && [ "$(grep -c "已连上 y port:$ECHO(经 y)" "$T/x.log")" -ge 2 ]'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 20 "$T"/*.log; }
[ $fail -eq 0 ]
