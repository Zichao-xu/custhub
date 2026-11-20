#!/usr/bin/env bash
# 传文件(本机多进程): custhub send / pull; 放进目录、中文和空格路径、断了续传、内容核对、权限
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=$((20000 + RANDOM % 20000)); PR=$base PX=$((base+1))
export CUSTHUB_MESH_OBS_S=3600 CUSTHUB_IP6=
sum(){ sha256sum "$1" | cut -c1-64; }

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r x; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "node r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node x $(cat "$T/x.pub")"; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d"; cat "$T/d" "$T/d.sig" >"$T/t1"
i=0; for n in r x; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s\nupnp off\n' "$(cat "$T/master.pub")" $((base+20+i)) "$T/$n.log" >"$T/$n/conf"
  cp "$T/t1" "$T/$n/trust"
done
echo "listen 127.0.0.1:$PR" >>"$T/r/conf"; echo "listen 127.0.0.1:$PX" >>"$T/x/conf"
. ./testlib.sh
mkpass "$T/master" "$T/x/pass" "$(cat "$T/x.pub")" all "file"
$M run "$T/r" &
$M run "$T/x" &
wait_for 15 sh -c "$M ls $T/x | sed -n '/^链路/,/^位置/p' | grep -q '^  r '"
mkdir -p "$T/far" "$T/near"

echo "== 1 发送 / 拉取"
head -c 5000000 /dev/urandom >"$T/a.bin"
$M send "$T/x" "$T/a.bin" r "$T/far/" >/dev/null 2>&1
ok "send 到对方目录(以 / 结尾): 同名放进去, 内容一样" '[ "$(sum "$T/far/a.bin")" = "$(sum "$T/a.bin")" ]'
$M send "$T/x" "$T/a.bin" r "$T/far/b.bin" >/dev/null 2>&1
ok "send 到对方指定文件名" '[ "$(sum "$T/far/b.bin")" = "$(sum "$T/a.bin")" ]'
$M pull "$T/x" "$T/near" r "$T/far/b.bin" >/dev/null 2>&1
ok "pull 到本机目录: 同名放进去, 内容一样" '[ "$(sum "$T/near/b.bin")" = "$(sum "$T/a.bin")" ]'
o=$($M send "$T/x" "$T/a.bin" r "$T/没有这个目录/" 2>&1)
ok "对方目录不存在: 说清楚原因" 'echo "$o" | grep -q "对方写不了这个路径(目录不存在或没权限)"'
o=$($M pull "$T/x" "$T/near" r "$T/far/nope.bin" 2>&1)
ok "对方没有这个文件: 说清楚原因" 'echo "$o" | grep -q "对方没有这个文件"'

echo "== 2 中文、空格路径"
cp "$T/a.bin" "$T/测试 文件.bin"; mkdir -p "$T/far/收 件"
$M send "$T/x" "$T/测试 文件.bin" r "$T/far/收 件/" >/dev/null 2>&1
ok "中文和空格的文件名、目录名都行" '[ "$(sum "$T/far/收 件/测试 文件.bin")" = "$(sum "$T/a.bin")" ]'

echo "== 3 断了续传"
head -c 60000000 /dev/urandom >"$T/big.bin"
CUSTHUB_SEND_DELAY_MS=20 $M send "$T/x" "$T/big.bin" r "$T/far/" >/dev/null 2>&1 & sp=$!
wait_for 20 sh -c "[ \$(stat -c %s $T/far/big.bin.*.custhub-part 2>/dev/null || echo 0) -gt 3000000 ]"
kill -9 $sp 2>/dev/null; wait $sp 2>/dev/null; sleep 1
part=$(ls "$T"/far/big.bin.*.custhub-part 2>/dev/null | head -1); psz=$(stat -c %s "$part" 2>/dev/null || echo 0)
ok "断在半截: 对方留着没收完的部分(${psz} 字节), 目标文件还不存在" '[ -n "$part" ] && [ "$psz" -gt 0 ] && [ "$psz" -lt 60000000 ] && [ ! -e "$T/far/big.bin" ]'
o=$($M send "$T/x" "$T/big.bin" r "$T/far/" 2>&1)
ok "再执行同一条命令: 接着续传, 收完内容一样, 临时文件清掉" 'echo "$o" | grep -q "接着上次的" && [ "$(sum "$T/far/big.bin")" = "$(sum "$T/big.bin")" ] && ! ls "$T"/far/big.bin.*.custhub-part >/dev/null 2>&1'

echo "== 4 权限"
mv "$T/x/pass" "$T/x/pass.off"
o=$($M send "$T/x" "$T/a.bin" r "$T/far/c.bin" 2>&1); mv "$T/x/pass.off" "$T/x/pass"
ok "没有 file / sh 通行证的被拒, 对方不留文件" '[ ! -e "$T/far/c.bin" ] && echo "$o" | grep -qE "拒绝|通行证"'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 15 "$T"/*.log; }
[ $fail -eq 0 ]
