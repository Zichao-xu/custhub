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

echo "== 开机启动(假 root: setuid 的 su)"
H=/data/local/tmp/custhub; N=$H/node; B=/data/adb/service.d/custhub.sh
cat >/system/bin/getprop <<'G'
#!/bin/sh
[ "$1" = sys.boot_completed ] && { echo 1; exit; }
printf '[ro.product.model]: [M-1]\n[ro.build.version.release]: [12]\n'
G
cat >"$T/su.c" <<'G'
#include <unistd.h>
#include <stdio.h>
int main(int c, char **v) { FILE *f = fopen("/data/su.log", "a"); if (f) { fputs("su\n", f); fclose(f); } if (c < 3 || setgid(0) || setuid(0)) return 1; execl("/bin/sh", "sh", "-c", v[2], (char *)0); return 1; }
G
mksu(){ ${CC:-cc} -o /usr/local/bin/su "$T/su.c" && chmod 4755 /usr/local/bin/su; }
node(){ rm -rf "$H"; mkdir -p "$N" /data/adb/service.d; cp "$M" "$H/custhub"; cp "$T/x/trust" "$T/x/node.key" "$N/"; sed "s#$T/x.log#$N/x.log#" "$T/x/conf" >"$N/conf"; chown -R 2000:2000 "$H"; }
dpid(){ pgrep -f "custhub run $N" | while read -r q; do [ "$(cat /proc/$q/comm 2>/dev/null)" = custhub ] && echo "$q" && break; done; }
duid(){ awk '/^Uid:/{print $2}' "/proc/$(dpid)/status" 2>/dev/null; }
wt(){ local n=$1; shift; for _ in $(seq $((n*2))); do eval "$*" && return 0; sleep 0.5; done; return 1; }
killall9(){ for q in $(pgrep -f "custhub.sh loop"; pgrep -f "custhub run $N"); do kill -9 "$q" 2>/dev/null; done; sleep 1; }
rm -f /data/su.log; mkdir -p /data; touch /data/su.log; chmod 666 /data/su.log; mksu; node
setsid "$H/custhub" run "$N" >/dev/null 2>&1 </dev/null &
ok "root 起的守护降到 uid 2000" 'wt 10 "[ \"\$(duid)\" = 2000 ]"'
ok "守护自己补上开机脚本" 'wt 10 "[ -x $B ]" && wt 5 "head -1 $N/boot | grep -q ok"'
ok "杀掉守护, 5 秒多后自己拉起(uid 2000)" 'o=$(dpid); kill -9 $o; wt 15 "q=\$(dpid); [ -n \"\$q\" ] && [ \"\$q\" != $o ] && [ \"\$(duid)\" = 2000 ]"'
c1=$(wc -l </data/su.log)
ok "脚本没变: 再起不再要 root" 'killall9; sh $B; wt 15 "[ \"\$(duid)\" = 2000 ]" && sleep 2 && [ "$(wc -l </data/su.log)" = "$c1" ]'
ok "开机脚本重复执行只有一个循环" 'sh $B; sh $B; sleep 2; [ "$(pgrep -fc "custhub.sh loop")" = 1 ]'
setpriv --reuid 2000 --regid 2000 --clear-groups "$H/custhub" remove >/dev/null 2>&1; sleep 7
ok "remove(adb 身份): 脚本、进程、目录都没了, 不再复活" '[ ! -e $B ] && [ -z "$(dpid)" ] && [ -z "$(pgrep -f "custhub.sh loop")" ] && [ ! -e $H/custhub ]'
rm -f /usr/local/bin/su; rm -rf /data/adb; node
setsid setpriv --reuid 2000 --regid 2000 --clear-groups "$H/custhub" run "$N" >/dev/null 2>&1 </dev/null &
ok "没有 root: 照常运行, 记下没拿到" 'wt 10 "head -1 $N/boot 2>/dev/null | grep -q no" && [ "$(duid)" = 2000 ] && [ ! -e $B ]'
killall9; rm -rf /data
echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { echo "$J"; head -3 "$T/x.log"; exit 1; }
