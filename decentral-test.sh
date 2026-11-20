#!/usr/bin/env bash
# 去中心化(本机多进程): 协助不再只靠可达节点, 每个节点都能做
#   r: 可达节点(起头用, 之后关掉); x、y、z 都不可达(观察期很长)
#   y 监听所有地址(报局域网端点), x、z 只听 127.0.0.1、不打洞(TCP / UDP 都关) → x、z 之间没有直连, 都和 y 直连
#   1 关掉 r 后, x 连 z 的服务经 y(不可达)中转
#   2 新机器 n 只知道 y 的局域网地址, 直接向 y 报到(y 不可达也收)
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=$((20000 + RANDOM % 20000)); PR=$base PX=$((base+1)) PY=$((base+2)) PZ=$((base+3)) PN=$((base+4)) ECHO=$((base+5))
export CUSTHUB_MESH_OBS_S=3600 CUSTHUB_IP6=
LAN=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -E '^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.' | head -1)
[ -n "$LAN" ] || { echo "  (本机没有局域网 IPv4, 跳过)"; echo "== 结果: 通过 0, 失败 0"; exit 0; }

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r x y z n; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "node r $(cat "$T/r.pub") 127.0.0.1:$PR"; for n in x y z; do echo "node $n $(cat "$T/$n.pub")"; done; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d"; cat "$T/d" "$T/d.sig" >"$T/t1"
i=0; for n in r x y z n; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nallow %s\nlog %s\nupnp off\nhello host-%s\n' "$(cat "$T/master.pub")" $((base+20+i)) "$ECHO" "$T/$n.log" "$n" >"$T/$n/conf"
  cp "$T/t1" "$T/$n/trust"
done
echo "listen 127.0.0.1:$PR" >>"$T/r/conf"; echo "listen 0.0.0.0:$PY" >>"$T/y/conf"
for n in x z; do echo "listen 127.0.0.1:$(eval echo \$P$(echo $n | tr a-z A-Z))" >>"$T/$n/conf"; done
echo "listen 127.0.0.1:$PN" >>"$T/n/conf"
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
$M run "$T/y" &
for n in x z; do CUSTHUB_NO_TCP_PUNCH=1 CUSTHUB_NO_UDP=1 $M run "$T/$n" & done
direct(){ $M ls "$T/$1" | sed -n '/^链路/,/^位置/p' | grep -qE "^  $2 +(出站|入站) "; }

echo "== 1 关掉唯一的可达节点, 经不可达的 y 中转"
wait_for 30 sh -c "$M ls $T/x | sed -n '/^链路/,/^位置/p' | grep -qE '^  y +出站 $LAN:$PY' && $M ls $T/z | sed -n '/^链路/,/^位置/p' | grep -qE '^  y +出站 $LAN:$PY'"
ok "x、z 都经 y 的局域网端点直连 y" 'direct x y && direct z y'
ok "x、z 之间没有直连" '! direct x z'
wait_for 20 grep -q "挂在=[^ ]*z" <($M ls "$T/x" | grep "^  y ")
ok "y 的位置记录里「挂在」列出所有直连(含 x、z, 它们是连过来的)" '$M ls "$T/x" | grep "^  y " | grep -qE "挂在=[^ ]*x" && $M ls "$T/x" | grep "^  y " | grep -qE "挂在=[^ ]*z"'
kill $(pgrep -f "$M run $T/r") 2>/dev/null; sleep 2
ok "r 关掉后 x 连 z 的服务经 y 中转" '[ "$(printf hi | $M connect "$T/x" z $ECHO 2>/dev/null)" = hi ] && grep -q "已连上 z port:$ECHO(经 y)" "$T/x.log" && grep -q "转发 x → z" "$T/y.log"'

echo "== 2 新机器向不可达的 y 报到"
printf '%s %s:%s\n' "$(cat "$T/y.pub")" "$LAN" "$PY" >"$T/n/peers"   # n 只知道 y 的局域网地址
$M run "$T/n" &
wait_for 20 grep -qF "$(cat "$T/n.pub")" "$T/y/pending"
ok "y(不可达)收下 n 的报到, 进了待批准" 'grep -qF "$(cat "$T/n.pub")" "$T/y/pending"'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 20 "$T"/*.log; }
[ $fail -eq 0 ]
