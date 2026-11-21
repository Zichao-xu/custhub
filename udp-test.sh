#!/usr/bin/env bash
# UDP 链路(本机多进程): x、y 都连不进来(观察期很长)、没有局域网端点、关掉 TCP 打洞, 原来只能经 r 中转
#   UDP 查映射: 向可达节点 r 的 UDP 端口发 'W', 回 'w' + 映射, 写进位置记录(UDP打洞=)
#   UDP 打洞: 没有直接的 TCP 链路时, 公钥小的一方开 KCP 会话, 跑同一套 Noise 握手 + 帧
#   发出去的 UDP 包丢 20%(CUSTHUB_UDP_LOSS), 看 KCP 重传后 1MB 数据原样到达
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}; PR=$base PX=$((base+1)) PY=$((base+2)) ECHO=$((base+3))
export CUSTHUB_MESH_OBS_S=3600 CUSTHUB_IP6= CUSTHUB_NO_TCP_PUNCH=1

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
$M run "$T/r" &
for n in x y; do CUSTHUB_UDP_LOSS=20 $M run "$T/$n" & done
udp_link(){ $M ls "$T/x" | sed -n '/^链路/,/^位置/p' | grep -qE "^  y +UDP 127.0.0.1:$PY$"; }

echo "== 1 UDP 查映射"
wait_for 10 grep -q "UDP 监听 0.0.0.0:$PR" "$T/r.log"
ok "可达节点的 UDP 端口回 'w' + 请求方地址" '[ "$(python3 -c "
import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.bind((\"127.0.0.1\", $((base+40)))); s.sendto(b\"W\", (\"127.0.0.1\", $PR)); print(s.recv(100).decode())")" = "w127.0.0.1:$((base+40))" ]'
wait_for 30 grep -q "UDP打洞=127.0.0.1:$PY" <($M ls "$T/x")
ok "x 收到 y 的 UDP 打洞端点" '$M ls "$T/x" | grep -q "^  y .*UDP打洞=127.0.0.1:$PY"'
ok "x 的 ls 有 UDP 打洞一行" '$M ls "$T/x" | grep -q "^UDP 打洞: 127.0.0.1:$PX$"'

echo "== 2 UDP 打洞直连(丢 20% 的包)"
wait_for 40 udp_link
ok "x 和 y 之间有 UDP 链路" 'udp_link'
ok "没有 TCP 的直接链路(关了 TCP 打洞)" '! $M ls "$T/x" | sed -n "/^链路/,/^位置/p" | grep -qE "^  y +(出站|入站|打洞) "'
head -c 1048576 /dev/urandom >"$T/big"
ok "x 经 UDP 连 y 的服务, 1MB 原样回来" '[ "$($M connect "$T/x" y $ECHO <"$T/big" 2>/dev/null | head -c 1048576 | sha256sum | cut -c1-64)" = "$(sha256sum <"$T/big" | cut -c1-64)" ] && grep -q "已连上 y port:$ECHO(经 y)" "$T/x.log"'

echo "== 3 y 下线: UDP 链路断开, 照旧经 r"
kill $(pgrep -f "$M run $T/y") 2>/dev/null
wait_for 15 grep -q "链路断开 y" "$T/x.log"
ok "x 发现 UDP 链路断了" 'grep -q "链路断开 y" "$T/x.log"'
CUSTHUB_UDP_LOSS=20 $M run "$T/y" &
wait_for 15 grep -c "链路建立 r" "$T/y.log"
ok "y 回来后 x 连 y 的服务照样通" 'wait_for 20 sh -c "[ \"\$(printf hi | $M connect $T/x y $ECHO 2>/dev/null)\" = hi ]"'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 20 "$T"/*.log; }
[ $fail -eq 0 ]
