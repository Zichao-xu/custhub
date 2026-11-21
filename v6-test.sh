#!/usr/bin/env bash
# 双栈热备(本机多进程, 用 ::1 当 IPv6): IPv4、IPv6 分开测、分开算可达; 同一对端两条链路同时挂着, 新流量优先 IPv6, IPv6 断了马上走 IPv4, 恢复后再回到 IPv6
#   r: IPv4 127.0.0.1 + IPv6 [::1](announce6 指到一个转发器, 杀掉转发器 = IPv6 断线)
#   a: 普通节点(relay off), 有 IPv6 出口(替 r 测 IPv6), 挂到 r 上, 连 r 的 echo
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; pkill -f "$T/fwd.py" 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}; PR=$base PR6=$((base+1)) PX=$((base+2)) ECHO=$((base+3))
export CUSTHUB_IP6=::1 CUSTHUB_MESH_OBS_S=3 CUSTHUB_MESH_PROBE_S=600

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r a; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "node r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node a $(cat "$T/a.pub")"; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d"; cat "$T/d" "$T/d.sig" >"$T/t1"
i=0; for n in r a; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nallow %s\nlog %s\nupnp off\n' "$(cat "$T/master.pub")" $((base+10+i)) "$ECHO" "$T/$n.log" >"$T/$n/conf"
  cp "$T/t1" "$T/$n/trust"
done
printf 'listen 127.0.0.1:%s\nlisten6 [::1]:%s\nannounce6 [::1]:%s\n' $PR $PR6 $PX >>"$T/r/conf"
echo "relay off" >>"$T/a/conf"
cat >"$T/fwd.py" <<'EOF'
import socket, sys, threading
s = socket.socket(socket.AF_INET6); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("::1", int(sys.argv[1]))); s.listen(8)
def pipe(x, y):
    try:
        while True:
            d = x.recv(65536)
            if not d: break
            y.sendall(d)
    except OSError: pass
    for z in (x, y):
        try: z.shutdown(socket.SHUT_RDWR)
        except OSError: pass
while True:
    c, _ = s.accept(); u = socket.create_connection(("::1", int(sys.argv[2])))
    for z in (c, u): z.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   # 不然小包被攒 40ms, IPv6 测出来比 IPv4 慢, 选路就换成 IPv4
    threading.Thread(target=pipe, args=(c, u), daemon=True).start(); threading.Thread(target=pipe, args=(u, c), daemon=True).start()
EOF
fwd(){ python3 "$T/fwd.py" $PX $PR6 >/dev/null 2>&1 & }
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
mkpass "$T/master" "$T/a/pass" "$(cat "$T/a.pub")" all "port:*"
fwd
for n in r a; do $M run "$T/$n" & done
v6up(){ $M ls "$T/a" | grep -qE "^  r +\[::1\]:$PX +通$"; }
v4up(){ $M ls "$T/a" | grep -qE "^  r +127.0.0.1:$PR +通$"; }
echo_ok(){ [ "$(printf "$1" | $M connect "$T/a" r $ECHO 2>/dev/null)" = "$1" ]; }

echo "== 1 IPv4、IPv6 分开测、分开算可达"
wait_for 20 grep -q "可达: 对外地址 \[::1\]:$PX" "$T/r.log"
ok "r 的 IPv4 可达(名单老种子免观察)" 'grep -q "可达: 对外地址 127.0.0.1:$PR" "$T/r.log"'
ok "r 的 IPv6 由 a 回连测试通过、过了观察期才算可达" 'grep -q "IPv6 端口: 已开启: \[::1\]:$PX 从外面连得进来, 观察期中" "$T/r.log" && grep -q "可达: 对外地址 \[::1\]:$PX(过了观察期)" "$T/r.log"'
ok "r 的 ls 有 IPv6 一行" '$M ls "$T/r" | grep -q "^IPv6: 已开启: \[::1\]:$PX 从外面连得进来, 可达"'
wait_for 15 grep -q "IPv6=\[::1\]:$PX" <($M ls "$T/a")
ok "a 收到 r 的位置记录带 IPv6 地址" '$M ls "$T/a" | grep -q "^  r .*IPv6=\[::1\]:$PX"'
ok "a 自己报了有 IPv6 出口但不可达(6=-)" '$M ls "$T/r" | grep -q "^  a .*IPv6=-"'

echo "== 2 两条链路同时挂着, 新流量优先 IPv6"
wait_for 20 v6up
ok "a 到 r: IPv4、IPv6 两条都通" 'v4up && v6up'
ok "a 连 r 的服务走 IPv6" 'echo_ok hi6 && grep -q "已连上 r port:$ECHO(经 r, IPv6)" "$T/a.log"'

echo "== 3 IPv6 断了马上走 IPv4(不用重新拨号)"
pkill -f "$T/fwd.py"; : >"$T/a.log.mark"; n0=$(grep -c "已连上 r port:$ECHO(经 r)$" "$T/a.log")
wait_for 12 grep -q "链路断开 r" "$T/a.log"
ok "IPv6 链路断开, IPv4 那条还在" 'grep -q "链路断开 r" "$T/a.log" && v4up'
ok "马上连 r 的服务: 走 IPv4, 照样通" 'echo_ok hi4 && [ "$(grep -c "已连上 r port:$ECHO(经 r)$" "$T/a.log")" -gt "$n0" ]'

echo "== 4 IPv6 恢复后新流量回到 IPv6"
fwd; sleep 0.5
wait_for 20 v6up
n6=$(grep -c "(经 r, IPv6)" "$T/a.log")
ok "IPv6 重新挂上, 新流量又走 IPv6" 'v6up && echo_ok hi66 && [ "$(grep -c "(经 r, IPv6)" "$T/a.log")" -gt "$n6" ]'

echo "== 5 地址簿、种子带 IPv6"
B64R=$(cat "$T/r.pub")
ok "a 的地址簿记下 r 的 IPv4 和 IPv6" 'grep -q "^$B64R 127.0.0.1:$PR \[::1\]:$PX$" "$T/a/peers"'
$M key --dir "$T/r" seed --github o/r --out "$T/seed" 2>/dev/null
ok "r 出的种子 hint 行带 IPv6" 'grep -q "^hint $B64R 127.0.0.1:$PR \[::1\]:$PX$" "$T/seed"'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 25 "$T"/*.log; }
[ $fail -eq 0 ]
