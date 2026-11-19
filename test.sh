#!/usr/bin/env bash
# 网络层 POC 验收(design-v3 §7 第 1 段), 本机多进程: 两台中继 r1 r2 + 两台"NAT 后"节点 a b(不监听, 只出站)
#   1 a 经中继连 b 的本机服务: 小消息原样回显 + 8MB 大流量校验(额度/背压)
#   2 中继读不到内容: 中继把转发的 DATA 原样落盘, 里面找不到明文标记
#   3 关一台中继, 10 秒内经另一台连通
#   4 中继换地址(名单没改), 靠位置记录互传, 节点自己找回去
#   5 中继全换地址, 节点靠兜底来源拿到新名单找回去
#   6 不放行的端口被拒; 名单外的节点被拒; 没有 / 不对的通行证被拒(默认拒绝)
#   7 通行证即入场券: 名单外的 g 持证挂上中继当访客, 只能连通行证 to 里的机器
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) ${SSH_AGENT_PID:-} 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
base=$((20000 + RANDOM % 20000))
P1=$base P2=$((base+1)) P1B=$((base+2)) P1C=$((base+3)) P2C=$((base+4)) ECHO=$((base+5))

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r1 r2 a b x; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
mktrust(){  # mktrust 版本 r1地址 r2地址 → stdout
  { echo "custhub-mesh-trust $1"
    echo "relay r1 $(cat "$T/r1.pub") $2"
    echo "relay r2 $(cat "$T/r2.pub") $3"
    echo "node a $(cat "$T/a.pub")"
    echo "node b $(cat "$T/b.pub")"
    echo "--end--"; } >"$T/data"
  ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/data" 2>/dev/null
  cat "$T/data" "$T/data.sig"; rm -f "$T/data.sig"
}
mktrust 1 127.0.0.1:$P1 127.0.0.1:$P2 >"$T/trust1"
MASTER=$(cat "$T/master.pub")
. ./testlib.sh
eval "$(ssh-agent -s)" >/dev/null; ssh-add -q "$T/master" 2>/dev/null   # 主钥匙只在 agent 里, mesh pass 问它要签名
conf(){  # conf 名字 ctl端口 [listen/announce 端口]
  { echo "master $MASTER"; echo "ctl 127.0.0.1:$2"
    [ -n "${3:-}" ] && { echo "listen 127.0.0.1:$3"; echo "announce 127.0.0.1:$3"; echo "dump 1"; }
    [ -z "${3:-}" ] && echo "relay off"                 # 同一台机器上起好几个节点: 只让 r1 / r2 开监听
    echo "upnp off"                                     # 测试不碰真路由器
    [ "$1" = b ] && echo "allow 22 $ECHO"
    [ "$1" = a ] || [ "$1" = b ] && echo "fallback $T/fallback"
  } >"$T/$1/conf"
}
conf r1 $((base+11)) $P1; conf r2 $((base+12)) $P2; conf a $((base+13)); conf b $((base+14))
for n in r1 r2 a b; do cp "$T/trust1" "$T/$n/trust"; done
start(){ $M run "$T/$1" >>"$T/$1.log" 2>&1 & eval "PID_$1=$!"; }
$M pass "$T/a" --to all --svc "port:*" 2>/dev/null || echo "  ✘ mesh pass 给 a 签发失败"   # a 凭通行证连 b
for n in r1 r2 a b; do start $n; done

# b 上的被访问服务: 回显
python3 - "$ECHO" <<'EOF' >"$T/echo.log" 2>&1 &
import socket, sys, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16)
def h(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
EOF

waitfor(){  # waitfor 秒 命令… → 返回用了多少秒(打印), 超时返回 1
  local lim=$1; shift; local t0=$(perl -MTime::HiRes=time -e 'printf "%.0f", time*1000')
  while :; do
    "$@" >/dev/null 2>&1 && { perl -MTime::HiRes=time -e "printf '%.1f', (time*1000-$t0)/1000"; return 0; }
    [ $(( $(perl -MTime::HiRes=time -e 'printf "%.0f", time*1000') - t0 )) -gt $((lim*1000)) ] && return 1
    sleep 0.2
  done
}
both_up(){ $M ls "$T/$1" | awk '/^挂中继/{f=1;next} /^链路/{f=0} f' | grep -c ' 通$' | grep -qx 2; }
echo_ok(){ local o; o=$(printf 'ping-%s' "$1" | $M connect "$T/a" b $ECHO 2>&1); echo "$(date +%T) [$1] [$o]" >>"$T/echo_ok.log"; [ "$o" = "ping-$1" ]; }

echo "== 启动"
s=$(waitfor 15 both_up a) && s2=$(waitfor 15 both_up b) && ok "a、b 都挂上两台中继(${s}s / ${s2}s)" || ng "挂中继超时"

echo "== 1 经中继连通"
MARK="MARK-$RANDOM-plaintext-should-never-appear"
out=$(printf '%s' "$MARK" | $M connect "$T/a" b $ECHO)
[ "$out" = "$MARK" ] && ok "小消息原样回显" || ng "回显不对: [$out]"
head -c 8000000 /dev/urandom >"$T/big"
t0=$(perl -MTime::HiRes=time -e 'print time')
$M connect "$T/a" b $ECHO <"$T/big" >"$T/big.back"
t1=$(perl -MTime::HiRes=time -e 'print time')
if cmp -s "$T/big" "$T/big.back"; then ok "8MB 往返一致($(perl -e "printf '%.1f', 16/($t1-$t0)") MB/s 双向合计)"; else ng "8MB 往返不一致($(wc -c <"$T/big.back") 字节)"; fi

echo "== 2 中继读不到内容"
cat "$T/r1/dump" "$T/r2/dump" 2>/dev/null >"$T/dumps"
dsz=$(wc -c <"$T/dumps" | tr -d ' ')
if [ "$dsz" -gt 1000000 ] && ! grep -qa "$MARK" "$T/dumps"; then ok "中继转发了 $dsz 字节, 其中没有明文标记"; else ng "dump ${dsz} 字节 / 或含明文"; fi

echo "== 3 关一台中继"
kill -9 $PID_r1; wait $PID_r1 2>/dev/null
s=$(waitfor 10 echo_ok k3) && ok "关掉 r1 后 ${s}s 经 r2 连通" || ng "关掉 r1 后 10 秒内连不通"

echo "== 4 中继换地址(名单没改, 靠位置记录互传)"
sed -i.bak "s/:$P1\$/:$P1B/" "$T/r1/conf"; rm -f "$T/r1/conf.bak"
start r1
r1_new(){ $M ls "$T/a" | grep -E "^  r1 .*127.0.0.1:$P1B .*通$"; }
s=$(waitfor 20 r1_new) && ok "r1 换到 :$P1B 后 a ${s}s 找回并挂上" || ng "a 没找回 r1"
kill -9 $PID_r2; wait $PID_r2 2>/dev/null
s=$(waitfor 10 echo_ok k4) && ok "再关 r2, ${s}s 经新地址的 r1 连通" || ng "只剩新地址 r1 时连不通"

echo "== 5 中继全换地址(兜底来源)"
kill -9 $PID_r1; wait $PID_r1 2>/dev/null
mktrust 2 127.0.0.1:$P1C 127.0.0.1:$P2C >"$T/trust2"
sed -i.bak "s/:$P1B\$/:$P1C/" "$T/r1/conf"; sed -i.bak "s/:$P2\$/:$P2C/" "$T/r2/conf"; rm -f "$T"/r?/conf.bak
cp "$T/trust2" "$T/r1/trust"; cp "$T/trust2" "$T/r2/trust"
start r1; start r2
sleep 1; cp "$T/trust2" "$T/fallback"
s=$(waitfor 30 echo_ok k5) && ok "兜底来源给出新名单后 ${s}s 连通" || ng "全换地址后 30 秒内没找回"
grep -q "名单 v1 → v2(来自 兜底来源)" "$T/a.log" && ok "a 的名单经兜底升到 v2" || ng "a 没从兜底拿名单"

echo "== 6 拒绝"
o=$(printf x | $M connect "$T/a" b 9 2>&1); echo "$o" | grep -q "端口不开放" && ok "不放行端口被拒: $o" || ng "端口 9 没被拒: $o"
cp "$T/a/pass" "$T/a.pass.good"
rej(){  # rej 说明 期望原因; 用 a 现在的 pass 连 b 的回显口
  local o; o=$(printf x | $M connect "$T/a" b $ECHO 2>&1)
  echo "$o" | grep -q "$2" && ok "$1被拒: $o" || ng "$1没被拒: $o"
}
rm -f "$T/a/pass";                                                                rej "没有通行证(名单成员也一样)" "没有通行证"
mkpass "$T/master" "$T/a/pass" "$(cat "$T/a.pub")" "$(cat "$T/r1.pub")" "port:*";  rej "通行证 to 不含 b" "不含这台机器"
mkpass "$T/master" "$T/a/pass" "$(cat "$T/a.pub")" all "port:22";                  rej "通行证 svc 不含这个口" "不含这项服务"
mkpass "$T/master" "$T/a/pass" "$(cat "$T/a.pub")" all "port:*" -7200 -3600;       rej "过期的通行证" "已过期"
mkpass "$T/master" "$T/a/pass" "$(cat "$T/b.pub")" all "port:*";                   rej "发给别人的通行证" "不是发给这台机器的"
ssh-keygen -q -t ed25519 -N '' -C evil -f "$T/evil"
mkpass "$T/evil" "$T/a/pass" "$(cat "$T/a.pub")" all "port:*";                     rej "不是主钥匙签的通行证" "签名不对"
cp "$T/a.pass.good" "$T/a/pass"
cp "$T/trust2" "$T/x/trust"; conf x $((base+15)); printf "fallback /nonexistent\nhello host-x tunkey-abc\n" >>"$T/x/conf"
start x; sleep 3
xp=$(cat "$T/x.pub")
cat "$T"/r?/pending 2>/dev/null | awk -v k="$xp" '$1==k{f=1} END{exit !f}' && ok "名单外节点 x 被拒, 中继把它记进待批准(带自报信息)" || ng "名单外节点没进待批准"
grep -q "已向 .* 报到, 等批准" "$T/x.log" && ok "x 自己知道在等批准, 10 分钟后再报" || ng "x 没进等批准状态"
o=$(printf x | $M connect "$T/x" b $ECHO 2>&1); [ "$o" != x ] && ok "x 连不了 b($o)" || ng "x 居然连通了"

echo "== 7 访客(通行证即入场券)"
mkdir -p "$T/g"; $M keygen "$T/g" >"$T/g.pub"; cp "$T/trust2" "$T/g/trust"; conf g $((base+16)); printf "fallback /nonexistent\nhello host-g\n" >>"$T/g/conf"
$M pass "$T/a" --for "$(cat "$T/g.pub")" --to b --svc "port:*" --out "$T/g/pass" 2>/dev/null   # 名单外的 g 当访客
start g
g_up(){ $M ls "$T/g" | awk '/^挂中继/{f=1;next} /^链路/{f=0} f' | grep -q ' 通$'; }
s=$(waitfor 15 g_up) && ok "名单外的 g 凭通行证 ${s}s 挂上中继(没进待批准)" || ng "g 没以访客身份挂上"
grep -q "链路建立 .*访客" "$T/g.log" && ok "g 知道自己是访客" || ng "g 日志里没有访客链路"
g_echo(){ [ "$(printf 'hi-g' | $M connect "$T/g" b $ECHO)" = hi-g ]; }
s=$(waitfor 10 g_echo) && ok "访客 g 经中继连到 b(${s}s)" || ng "访客 g 连不到 b"
o=$(printf x | $M connect "$T/g" a 22 2>&1); echo "$o" | grep -q "不含这台机器" && ok "访客连通行证外的 a 被中继拦下: $o" || ng "访客连 a 没被拦: $o"
grep -qF "$(cat "$T/g.pub")" "$T"/r?/pending 2>/dev/null && ng "持证的 g 被记进了待批准" || ok "持证的 g 没被当成报到"
rm -f "$T/g/pass"; kill $PID_g 2>/dev/null; wait $PID_g 2>/dev/null; : >"$T/g.log"; start g; sleep 3
grep -q "已向 .* 报到, 等批准" "$T/g.log" && ok "收回通行证后 g 退回报到等批准" || ng "没证的 g 没退回报到"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 15 "$T"/a.log "$T"/b.log "$T"/r1.log; }
[ $fail -eq 0 ]
