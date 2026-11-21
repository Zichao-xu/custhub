#!/usr/bin/env bash
# 告警(本机多进程, Linux): custhub alerts on / status / off —— 当前用户登录时自启动 watch --notify(桌面自启动文件), 这次也马上起来
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; pkill -f "$M watch --notify" 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}
export HOME="$T/home"; mkdir -p "$HOME"
ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
mkdir -p "$T/x"; $M keygen "$T/x" >"$T/x.pub"
{ echo "custhub-mesh-trust 1"; echo "node x $(cat "$T/x.pub")"; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d"; cat "$T/d" "$T/d.sig" >"$T/x/trust"
printf 'master %s\nctl 127.0.0.1:%s\nlog %s\nupnp off\nlisten 127.0.0.1:%s\n' "$(cat "$T/master.pub")" $((base+20)) "$T/x.log" $base >"$T/x/conf"
$M run "$T/x" &
wait_for 10 $M ls "$T/x"

echo "== alerts"
ok "没开时 status 说关着" '$M alerts "$T/x" status | grep -q "告警: 关着"'
o=$($M alerts "$T/x" on 2>&1)
ok "on: 写好自启动, 这次也马上在后台跑起来" 'echo "$o" | grep -q "告警已开" && [ -f "$HOME/.config/autostart/custhub-alerts.desktop" ] && grep -q "watch $T/x --notify" "$HOME/.config/autostart/custhub-alerts.desktop" && wait_for 5 pgrep -f "$M watch $T/x --notify"'
ok "status 说开着" '$M alerts "$T/x" status | grep -q "告警: 开着"'
$M alerts "$T/x" off >/dev/null 2>&1
ok "off: 去掉自启动, 后台那份也停了" '[ ! -f "$HOME/.config/autostart/custhub-alerts.desktop" ] && wait_for 5 sh -c "! pgrep -f \"$M watch $T/x --notif[y]\""'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 12 "$T"/*.log; }
[ $fail -eq 0 ]
