#!/usr/bin/env bash
# Linux / OpenWrt 真装验收: ./posix-install-test.sh <ssh 目标(root@主机)> <ssh 端口> <平台名(如 linux-arm64)> <本机局域网地址>
#   真的 custhub join(OpenWrt: /usr/lib/custhub + procd; 其他 Linux: /opt/custhub + systemd), 测完 custhub remove, 确认没有残留
#   测试节点 relay off + upnp off: 不开监听、不碰路由器端口映射, 尽量不影响那台机器
#   本机: 可达节点 r + 管理员节点 adm(0.3.1) + 发布源; 那台装 0.3.0, 看到 adm 报的 0.3.1 就去取(curl / wget / uclient-fetch)、换上
set -uo pipefail
cd "$(dirname "$0")"
H=${1:?用法: ./posix-install-test.sh <root@主机> <ssh 端口> <平台名> <本机地址>}; HP=${2:?}; PL=${3:?}; ME=${4:?}
T=$(mktemp -d)
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
R(){ ssh -p "$HP" -o ConnectTimeout=10 "$H" "$@"; }
cleanup(){
  R 'D=/usr/lib/custhub; [ -f /etc/openwrt_release ] || D=/opt/custhub; [ -x /tmp/chi/custhub ] && /tmp/chi/custhub remove >/dev/null 2>&1; [ -x /etc/init.d/custhub ] && { /etc/init.d/custhub stop; /etc/init.d/custhub disable; rm -f /etc/init.d/custhub; }; command -v systemctl >/dev/null && { systemctl disable --now custhub 2>/dev/null; rm -f /etc/systemd/system/custhub.service; }; pkill -f "custhub run" 2>/dev/null; rm -rf "$D" /tmp/chi' >/dev/null 2>&1
  kill $(jobs -p) ${SSH_AGENT_PID:-} 2>/dev/null; wait 2>/dev/null
  [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"
}
trap cleanup EXIT
base=$((20000 + RANDOM % 20000)); PR=$base GH=$((base+1))
echo "== 构建"
OUT=$T/mesh VER=0.3.1 PLAT=mac ./build.sh >/dev/null || exit 1
M=$T/mesh
for v in 0.3.0 0.3.1; do OUTDIR=$T/b$v VER=$v ONLY=$PL ./build.sh release >/dev/null || exit 1; done
B0=$T/b0.3.0/custhub3-0.3.0-$PL B1=$T/b0.3.1/custhub3-0.3.1-$PL
eval "$(ssh-agent -s)" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C custhub-master -f "$T/master"; ssh-add -q "$T/master" 2>/dev/null
for n in r adm; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "relay r $(cat "$T/r.pub") $ME:$PR"; echo "node adm $(cat "$T/adm.pub")"; echo "--end--"; } >"$T/d1"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d1" 2>/dev/null; cat "$T/d1" "$T/d1.sig" >"$T/t1"
i=0; for n in r adm; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s/%s.log\nupnp off\n' "$(cut -d' ' -f1,2 "$T/master.pub")" $((base+10+i)) "$T" "$n" >"$T/$n/conf"; cp "$T/t1" "$T/$n/trust"
done
echo "relay off" >>"$T/adm/conf"
mkdir -p "$T/gh"; (cd "$T/gh" && exec python3 -m http.server "$GH" --bind 0.0.0.0) >/dev/null 2>&1 &
for n in r adm; do $M run "$T/$n" 2>/dev/null & done
K(){ $M key --dir "$T/adm" "$@"; }
sleep 2
K seed --github none/none --out "$T/seed" 2>/dev/null
printf 'upnp off\nrelay off\nrelease_base http://%s:%s/\n' "$ME" "$GH" >"$T/preconf"
D=$(R '[ -f /etc/openwrt_release ] && echo /usr/lib/custhub || echo /opt/custhub')

echo "== 1 join(真装到 $D)"
R "rm -rf /tmp/chi; mkdir -p /tmp/chi $D/node" && scp -q -P "$HP" "$B0" "$H":/tmp/chi/custhub && scp -q -P "$HP" "$T/seed" "$H":/tmp/chi/seed && scp -q -P "$HP" "$T/preconf" "$H":"$D/node/conf" && R 'chmod +x /tmp/chi/custhub' || { ng "拷不过去"; exit 1; }
R '/tmp/chi/custhub join --seed /tmp/chi/seed --wait 90' >"$T/join.out" 2>&1 &
wait_for 30 grep -q "接入码" "$T/join.out"
code=$(sed -n 's/^  接入码: \([0-9A-Z]\{3\}-[0-9A-Z]\{3\}\).*/\1/p' "$T/join.out")
[ -n "$code" ] && ok "join 显示接入码 $code(服务: $(sed -n 's/^  注册系统服务(\(.*\))$/\1/p' "$T/join.out"))" || { ng "join 输出: $(cat "$T/join.out")"; exit 1; }
wait_for 30 sh -c "$M key --dir $T/adm pending | grep -q $code"
K approve "$code" box1 >/dev/null 2>&1 && ok "管理员按接入码批准 box1" || ng "批准失败: $(K pending)"
wait_for 60 grep -q "已接入: 名字 box1" "$T/join.out"
grep -q "已接入: 名字 box1" "$T/join.out" && ok "join 显示已接入" || ng "join 输出: $(tail -4 "$T/join.out")"
o=$(R "ps w 2>/dev/null | grep '[c]usthub run' || ps -ef | grep '[c]usthub run'")
echo "$o" | grep -q "$D/custhub run $D/node" && ok "服务在跑: $D/custhub run $D/node" || ng "进程: $o"

echo "== 2 shell"
K pass --to box1 --svc sh 2>/dev/null
o=$(perl -e 'alarm 60; exec @ARGV' $M sh "$T/adm" box1 -- id -un </dev/null)
[ "$o" = root ] && ok "跑命令: id -un = root" || ng "id: [$o]"
o=$(perl -e 'alarm 60; exec @ARGV' $M sh "$T/adm" box1 -- 'cat /etc/openwrt_release 2>/dev/null | grep DISTRIB_DESCRIPTION || uname -sm' </dev/null)
[ -n "$o" ] && ok "那台机器: $o" || ng "没输出"

echo "== 3 升级"
cp "$B1" "$T/gh/custhub3-0.3.1-$PL"
K release 0.3.1 "$T/gh/custhub3-0.3.1-$PL" --out "$T/gh/custhub3.release" 2>/dev/null
wait_for 120 sh -c "R(){ ssh -p $HP -o ConnectTimeout=10 $H \"\$@\"; }; R '$D/custhub version' 2>/dev/null | grep -q 'custhub 0.3.1'"
o=$(R "$D/custhub version")
echo "$o" | grep -q "^custhub 0.3.1 $PL" && ok "取到 0.3.1、换上、接班: $o" || ng "升级后: [$o]"
wait_for 60 sh -c "ssh -p $HP $H 'grep -q \"0.3.1 转正\" $D/node/mesh.log'"
lg=$(R "grep -E 'custhub3-0.3.1|已换上|试用|转正|回滚' $D/node/mesh.log")
echo "$lg" | grep -q "取 custhub3-0.3.1-$PL: http://" && ok "包是从发布源下载的(系统自带的下载工具)" || ng "取包日志: $lg"
echo "$lg" | grep -q "0.3.1 转正" && ! echo "$lg" | grep -q "回滚" && ok "新版转正, 没有回滚" || ng "转正日志: $lg"
n=$(R "ps w 2>/dev/null | grep -c '[c]usthub run' || ps -ef | grep -c '[c]usthub run'")
[ "$n" = 1 ] && ok "只有一份 custhub 在跑(procd / systemd 没多拉一份)" || ng "在跑: $n 份"

echo "== 4 remove"
o=$(R '/tmp/chi/custhub remove' 2>&1); echo "    $o"
sleep 2
o=$(R "ls /etc/init.d/custhub /etc/systemd/system/custhub.service 2>/dev/null; ps w 2>/dev/null | grep '[c]usthub run'; ls -d $D 2>/dev/null; true")
[ -z "$o" ] && ok "服务定义、进程、安装目录都没了" || ng "残留: $o"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
