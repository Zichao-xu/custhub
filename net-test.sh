#!/usr/bin/env bash
# 诊断和网络变化(本机多进程): custhub ping / netcheck / bench; 心跳测延迟、按延迟选路; 本机网络变了马上重查重连(用 CUSTHUB_NET_SIG_FILE 模拟)
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}; PR=$base PX=$((base+1))
export CUSTHUB_MESH_OBS_S=3600 CUSTHUB_IP6=

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r x; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "node r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node x $(cat "$T/x.pub")"; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d"; cat "$T/d" "$T/d.sig" >"$T/t1"
i=0; for n in r x; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s\nupnp off\n' "$(cat "$T/master.pub")" $((base+20+i)) "$T/$n.log" >"$T/$n/conf"
  cp "$T/t1" "$T/$n/trust"
done
echo "listen 127.0.0.1:$PR" >>"$T/r/conf"; echo "listen 127.0.0.1:$PX" >>"$T/x/conf"
echo a >"$T/sig"
. ./testlib.sh
mkpass "$T/master" "$T/x/pass" "$(cat "$T/x.pub")" all "sh"
$M run "$T/r" &
CUSTHUB_NET_SIG_FILE="$T/sig" $M run "$T/x" &

echo "== 1 心跳测延迟, custhub ping"
wait_for 15 sh -c "$M ping $T/x r | grep -q '延迟 [0-9]*ms'"
ok "ping 列出到 r 的各条直连和延迟, 标出现在走的那条" '$M ping "$T/x" r | grep -qE "^  → TCP IPv4 +127.0.0.1:$PR .*延迟 [0-9]+ms" && $M ping "$T/x" r | grep -q "^走直连: TCP IPv4 127.0.0.1:$PR"'
wait_for 30 sh -c "$M ping $T/x r | grep -q '^  .*UDP .*延迟 [0-9]*ms'"
ok "UDP 热备那条也测出延迟" '$M ping "$T/x" r | grep -qE "^  . UDP .*延迟 [0-9]+ms"'
ok "名单里没有的名字报错" '! $M ping "$T/x" nobody 2>&1 | grep -q 走直连'

echo "== 2 custhub netcheck"
ok "netcheck 有入站、UPnP、IPv6、打洞、直连几项" 'o=$($M netcheck "$T/x"); for k in "能力:" "TCP 入站:" "UDP 入站:" "UPnP:" "IPv6:" "TCP 打洞:" "UDP 打洞:" "直连:"; do echo "$o" | grep -q "$k" || exit 1; done'
ok "netcheck 列出到 r 的直连和延迟" '$M netcheck "$T/x" | grep -qE "^  r +TCP IPv4 [0-9]+ms"'

echo "== 3 custhub bench 测速"
o=$($M bench "$T/x" r 2 2>&1); echo "$o" | sed 's/^/     /'
ok "bench 测出上传、下载速度(都大于 0)" 'echo "$o" | grep -qE "^上传 [0-9]*[1-9][0-9]*\.[0-9]+ MB/s|^上传 0\.[0-9]*[1-9]" && echo "$o" | grep -qE "^下载 [0-9]*[1-9][0-9]*\.[0-9]+ MB/s|^下载 0\.[0-9]*[1-9]"'
ok "bench 和 shell 同权限: 没有 shell 通行证的被拒" 'mv "$T/x/pass" "$T/x/pass.off"; ! $M bench "$T/x" r 1 >/dev/null 2>&1; r=$?; mv "$T/x/pass.off" "$T/x/pass"; [ $r = 0 ]'

echo "== 3b 高延迟线路: 窗口自动长大(回环加 25ms 单程延迟 = 来回 50ms; 固定 256KB 窗口最多约 5 MB/s)"
if command -v tc >/dev/null && tc qdisc add dev lo root netem delay 25ms 2>/dev/null; then
  sleep 6; o=$($M bench "$T/x" r 4 2>&1); tc qdisc del dev lo root 2>/dev/null; echo "$o" | grep -E "上传|下载" | sed 's/^/     /'
  dn=$(echo "$o" | sed -n 's/^下载 \([0-9.]*\) MB.*/\1/p')
  ok "来回 50ms 时下载超过固定窗口的上限(固定 256KB 约 5 MB/s; 要 > 6.5, 实测 $dn)" 'awk -v d="$dn" "BEGIN{exit !(d > 6.5)}"'
else echo "  (没有 tc / netem, 跳过)"; fi

echo "== 4 网络变了马上重查重连"
echo b >"$T/sig"
wait_for 10 grep -q "本机网络变了" "$T/x.log"
ok "发现网络变了" 'grep -q "本机网络变了" "$T/x.log"'
sleep 5
ok "还活着的链路照常(3 秒内回了心跳, 没被关)" '! grep -q "本机网络变了, 这条没回音" "$T/x.log" && $M ping "$T/x" r | grep -q "^走直连"'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 20 "$T"/*.log; }
[ $fail -eq 0 ]
