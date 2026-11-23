#!/usr/bin/env bash
# 安卓信息(只在 Linux 容器里跑: 要往 /system/bin 放假的 getprop / date): 同一份 Linux 程序运行时认出安卓, 报对平台、系统、机型、日志时区, 且没有假文件时照旧
set -uo pipefail
cd "$(dirname "$0")"
[ "$(uname -s)" = Linux ] && [ "$(id -u)" = 0 ] && [ ! -e /system ] || { echo "== 结果: 通过 0, 失败 0(跳过: 只在 Linux 容器里跑)"; exit 0; }
./build.sh >/dev/null || exit 1
M=$PWD/mesh; T=$(mktemp -d); D=
trap 'kill $D 2>/dev/null; rm -rf "$T" /system' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
OUT=$T/mesh VER=0.0.0 PLAT=linux-arm64 CC=${CC:-cc} ./build.sh >/dev/null 2>&1 || exit 1
M=$T/mesh; P=${PORT_BASE:-27000}
ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"; mkdir -p "$T/x"; "$M" keygen "$T/x" >"$T/x.pub"
{ echo "custhub-mesh-trust 1"; echo "node x $(cat "$T/x.pub")"; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d" 2>/dev/null; cat "$T/d" "$T/d.sig" >"$T/x/trust"
printf 'master %s\nctl 127.0.0.1:%s\nlog %s/x.log\nupnp off\nrelay off\n' "$(cat "$T/master.pub")" "$P" "$T" >"$T/x/conf"
info(){ rm -f "$T/x.log"; "$M" run "$T/x" >/dev/null 2>&1 & D=$!; for _ in $(seq 40); do J=$("$M" inventory "$T/x" --json 2>/dev/null) && [ -n "$J" ] && break; sleep 0.25; done; kill $D; wait $D 2>/dev/null; D=; }
info; ok "不是安卓: 平台照旧 linux-arm64" 'echo "$J" | grep -q "\"platform\":\"linux-arm64\""'
mkdir -p /system/bin
cat >/system/bin/getprop <<'G'
#!/bin/sh
printf '[ro.product.manufacturer]: [Acme]\n[ro.product.model]: [M-1]\n[ro.product.marketname]: [Phone One]\n[ro.build.version.release]: [12]\n[ro.build.version.incremental]: [V1.2]\n[empty]: []\n'
G
printf '#!/bin/sh\necho +0530\n' >/system/bin/date; chmod +x /system/bin/getprop /system/bin/date
info
ok "平台 android-arm64" 'echo "$J" | grep -q "\"platform\":\"android-arm64\""'
ok "系统 Android 12 (V1.2)" 'echo "$J" | grep -q "\"os\":\"Android 12 (V1.2)\""'
ok "机型 Acme M-1" 'echo "$J" | grep -q "\"model\":\"Acme M-1\""'
ok "日志按手机时区记" 'H=$(TZ="<+0530>-05:30" date +%H:%M); head -1 "$T/x.log" | grep -qE " ($H|$(TZ="<+0530>-05:30" date -d "-1 min" +%H:%M)):"'
echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { echo "$J"; head -3 "$T/x.log"; exit 1; }
