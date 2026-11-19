#!/usr/bin/env bash
# 可达节点资质 + 批准流程(design-v3 §0 第 14 条: 可达节点是功能, 自检自动开关; 没有中转专用软件), 本机多进程
#   r: 名单里带地址(种子线索), conf 里不写监听 → 按名单里的端口开监听, 回连测试通过就算可达(免观察期)
#   adm: 管理员的普通节点(relay off); b: 普通节点, 开着监听; c: 名单外, 报到等批准(relay off)
#   1 种子线索 + 自检  2 报到拿到名单、进待批准、当场测端口  3 待批准只答主钥匙当场签的查询
#   4 管理员节点交新名单 → 沿链路传开, c 下次报到拿到后接入  5 b 不在名单里标可达节点: 回连通过 + 观察期后自己算可达, 别人挂上来
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
base=$((20000 + RANDOM % 20000)); PR=$base PB=$((base+1)) ECHO=$((base+2)) PC=$((base+3)) PD=$((base+4))
export CUSTHUB_MESH_PENDING_S=3 CUSTHUB_MESH_OBS_S=6      # 观察期缩到 6 秒

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"; ssh-keygen -q -t ed25519 -N '' -C evil -f "$T/evil"
for n in r adm b c d; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
sign(){  # sign 版本 正文… (KEY 可换钥匙)
  local v=$1; shift
  { echo "custhub-mesh-trust $v"; printf '%s\n' "$@"; echo "--end--"; } >"$T/data"
  ssh-keygen -q -Y sign -f "${KEY:-$T/master}" -n custhub-mesh-trust "$T/data"; cat "$T/data" "$T/data.sig"; rm -f "$T/data.sig"
}
L1=("relay r $(cat "$T/r.pub") 127.0.0.1:$PR" "node adm $(cat "$T/adm.pub")" "node b $(cat "$T/b.pub")" "node d $(cat "$T/d.pub")")
sign 1 "${L1[@]}" >"$T/t1"
i=0; for n in r adm b c d; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nallow %s\nfallback %s\nhello host-%s linux 0.2.0 port=2200%s\nlog %s\n' \
    "$(cat "$T/master.pub")" $((base+10+i)) "$ECHO" "$T/$n/trust.pull" "$n" "$i" "$T/$n.log" >"$T/$n/conf"
  echo "upnp off" >>"$T/$n/conf"                        # 测试不碰真路由器
  case $n in adm) echo "relay off" >>"$T/$n/conf" ;; b) echo "listen 127.0.0.1:$PB" >>"$T/$n/conf" ;; c) echo "listen 127.0.0.1:$PC" >>"$T/$n/conf" ;;
    d) printf 'listen 127.0.0.1:%s\nannounce 127.0.0.1:1\n' $PD >>"$T/$n/conf" ;; esac   # d 报的地址没人听: 回连不通
  cp "$T/t1" "$T/$n/trust"
done
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
mkpass "$T/master" "$T/adm/pass" "$(cat "$T/adm.pub")" all "port:*"   # adm 凭通行证连别人; c 批准后才发
for n in r adm b c d; do $M run "$T/$n" & done
ctl(){ $M ctl "$T/$1" "$2"; }
up(){ $M ls "$T/$1" | grep -qE "^  $2 .* 通$"; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }

echo "== 1 种子线索 + 自检"
wait_for 10 up adm r; wait_for 10 up b r
wait_for 10 grep -q "可达: 对外地址" "$T/r.log"
ok "r 按名单里的端口开了监听(conf 里没写)" 'grep -q "监听 0.0.0.0:$PR" "$T/r.log"'
ok "r 回连测试通过就算可达(种子线索免观察期)" 'grep -q "可达: 对外地址 127.0.0.1:$PR(种子线索, 免观察)" "$T/r.log"'
ok "relay off 的 adm 不开监听" '! grep -q "监听" "$T/adm.log"'
wait_for 10 sh -c "$M ls $T/d | grep -q 端口:.不通"
ok "d 报的地址连不进来: 端口显示不通, 不算可达" '$M ls "$T/d" | grep -q "端口: 不通" && ! grep -q "可达: 对外地址" "$T/d.log"'
ok "adm、b 挂上 r" 'up adm r && up b r'
ok "adm 经 r 连 b" '[ "$(printf hi | $M connect "$T/adm" b $ECHO)" = hi ]'

echo "== 2 名单外节点报到"
wait_for 10 grep -q "等批准" "$T/c.log"
ok "c 报到后进入等批准, 没算接入" 'grep -q "等批准" "$T/c.log" && $M ls "$T/c" | head -1 | grep -q "还没被批准"'
ok "c 连不了 b" '! printf x | $M connect "$T/c" b $ECHO >/dev/null 2>&1'
wait_for 10 sh -c "$M ls $T/c | grep -q 端口:.已开启"
ok "c 还没批准就测了端口: 当场显示已开启" '$M ls "$T/c" | grep -q "端口: 已开启: 127.0.0.1:$PC"'
ok "r 记下了 c(含回拨口)" 'grep -qF "$(cat "$T/c.pub")" "$T/r/pending" && grep -q "port=22004" "$T/r/pending"'

echo "== 3 待批准只答主钥匙当场签的查询"
q(){  # q 钥匙 时间戳 → 查询结果
  echo "custhub-mesh-pending $2" >"$T/q"; rm -f "$T/q.sig"
  ssh-keygen -q -Y sign -f "$1" -n custhub-mesh-pending "$T/q"
  ctl adm "PENDQ $(cat "$T/q" "$T/q.sig" | base64 | tr -d '\n')"
}
o=$(q "$T/master" "$(date +%s)")
ok "主钥匙签的查询拿到 c" 'printf "%s" "$o" | grep -qF "$(cat "$T/c.pub")"'
o=$(q "$T/evil" "$(date +%s)")
ok "陌生钥匙签的查询不答" '! printf "%s" "$o" | grep -qF "$(cat "$T/c.pub")" && printf "%s" "$o" | grep -q 没回答'
o=$(q "$T/master" "$(( $(date +%s) - 3600 ))")
ok "一小时前签的旧查询不答(防重放)" '! printf "%s" "$o" | grep -qF "$(cat "$T/c.pub")"'

echo "== 4 管理员节点交新名单"
KEY=$T/evil sign 2 "${L1[@]}" "node c $(cat "$T/c.pub")" >"$T/t-evil"
o=$(ctl adm "TRUSTPUT $(base64 <"$T/t-evil" | tr -d "\n")"); echo "    回答: $o"
ok "陌生钥匙签的名单不收" 'printf "%s" "$o" | grep -q "^ERR"'
sign 2 "${L1[@]}" "node c $(cat "$T/c.pub")" >"$T/t2"
ok "主钥匙签的 v2 收下" 'ctl adm "TRUSTPUT $(base64 <"$T/t2" | tr -d "\n")" | grep -q "v1 → v2"'
wait_for 10 grep -q "名单 v1 → v2" "$T/b.log"
ok "沿链路传到 b(经 r)" 'grep -q "名单 v1 → v2" "$T/b.log" && grep -q "名单 v1 → v2" "$T/r.log"'
wait_for 20 up c r
ok "c 下次报到拿到 v2 后接入" 'up c r'
mkpass "$T/master" "$T/c/pass" "$(cat "$T/c.pub")" all "port:*"
ok "c 现在能连 b" '[ "$(printf hi-c | $M connect "$T/c" b $ECHO)" = hi-c ]'

echo "== 5 b 不在名单里标可达节点, 自检 + 观察期后自己算可达"
ok "b 不是种子线索, 回连通过后先进观察期" 'grep -q "端口: 已开启: 127.0.0.1:$PB 从外面连得进来, 观察期中\|可达: 对外" <($M ls "$T/b"; cat "$T/b.log")'
wait_for 20 grep -q "可达: 对外地址 127.0.0.1:$PB(过了观察期)" "$T/b.log"
ok "过了观察期 b 自己算可达, 地址是回连测出来的" 'grep -q "可达: 对外地址 127.0.0.1:$PB(过了观察期)" "$T/b.log"'
wait_for 15 up adm b; wait_for 15 up c b
ok "adm、c 从 b 的位置记录得知它是可达节点, 自动挂上" 'up adm b && up c b'
kill -9 $(pgrep -f "$M run $T/r") 2>/dev/null; sleep 1
ok "关掉种子 r 后 c 经 b 仍能连 b 的服务" '[ "$(printf hi-b | $M connect "$T/c" b $ECHO)" = hi-b ]'
ok "relay off 的 adm 始终没算可达" '! grep -q "可达: 对外地址" "$T/adm.log"'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 12 "$T"/*.log; }
[ $fail -eq 0 ]
