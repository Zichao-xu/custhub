#!/usr/bin/env bash
# 给人和 AI 用的: custhub inventory(所有机器的基本信息, 不连机器) / custhub exec(多台并行跑命令, 输出一样的合并, --json)
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=$((20000 + RANDOM % 20000)); PR=$base PX=$((base+1)) PY=$((base+2))
export CUSTHUB_MESH_OBS_S=3600 CUSTHUB_IP6=

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r x y z; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "node r $(cat "$T/r.pub") 127.0.0.1:$PR"; for n in x y z; do echo "node $n $(cat "$T/$n.pub")"; done; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d"; cat "$T/d" "$T/d.sig" >"$T/t1"
i=0; for n in r x y; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s\nupnp off\n' "$(cat "$T/master.pub")" $((base+20+i)) "$T/$n.log" >"$T/$n/conf"
  cp "$T/t1" "$T/$n/trust"
done
echo "listen 127.0.0.1:$PR" >>"$T/r/conf"; echo "listen 127.0.0.1:$PX" >>"$T/x/conf"; echo "listen 127.0.0.1:$PY" >>"$T/y/conf"
. ./testlib.sh
mkpass "$T/master" "$T/x/pass" "$(cat "$T/x.pub")" all "sh"
for n in r x y; do $M run "$T/$n" & done
wait_for 20 sh -c "$M inventory $T/x --json | grep -q '\"name\":\"y\",\"self\":false,\"online\":true'"

echo "== 1 inventory"; $M inventory "$T/x" | sed "s/^/     /"
ok "列出所有成员: 本机、在线的、从没见过的(z)" '$M inventory "$T/x" | grep -qE "^x +本机" && $M inventory "$T/x" | grep -qE "^r +在线" && $M inventory "$T/x" | grep -qE "^z +离线 .*从没见过"'
ok "--json 是合法 JSON, 字段齐(系统、版本、能力、本机到它怎么连)" '$M inventory "$T/x" --json | python3 -c "
import json,sys; a=json.load(sys.stdin); r=[m for m in a if m[\"name\"]==\"r\"][0]
assert r[\"online\"] and r[\"platform\"] and r[\"version\"] and r[\"capability\"]==\"public\" and r[\"link\"][\"kind\"] in (\"tcp4\",\"udp\") and r[\"link\"][\"rtt_ms\"]>=0"'

echo "== 2 exec: 多台并行, 输出一样的合并"
o=$($M exec "$T/x" r,y -- echo hello 2>&1)
ok "两台输出一样: 合成一组, 显示两台的名字" 'echo "$o" | grep -qE "^── r y  ✔ 退出码 0" && echo "$o" | grep -qx "hello" && echo "$o" | grep -q "(2 台, 成功 2"'
o=$($M exec "$T/x" @online -- 'echo $(hostname)-$$' 2>&1)
ok "@online 分组: 不含本机, 输出不同的各自一组" '[ "$(echo "$o" | grep -c "^── ")" = 2 ] && ! echo "$o" | grep -q "^── x"'
o=$($M exec "$T/x" r -- 'echo bad; exit 3' 2>&1); rc=$?
ok "退出码带回来, 有失败时 custhub 也返回非 0" 'echo "$o" | grep -q "✘ 退出码 3" && [ $rc != 0 ]'

echo "== 3 --json / 超时 / 错误"
ok "--json: 每台一条, 有 ok / code / output / error" '$M exec "$T/x" r,y --json -- echo hi | python3 -c "
import json,sys; a=json.load(sys.stdin); assert len(a)==2 and all(x[\"ok\"] and x[\"code\"]==0 and x[\"output\"]==\"hi\" and x[\"error\"] is None for x in a)"'
o=$($M exec "$T/x" r --timeout 2 -- sleep 30 2>&1)
ok "超时: 标出来, 不卡住" 'echo "$o" | grep -q "✘ 超时"'
o=$($M exec "$T/x" nobody -- echo 2>&1); rc=$?
ok "名单里没有的名字: 说清楚, 返回用法错" 'echo "$o" | grep -q "名单里没有 nobody" && [ $rc = 2 ]'
o=$($M exec "$T/x" z -- echo hi 2>&1)
ok "不在线的机器: 标出连不上的原因" 'echo "$o" | grep -q "^── z  ✘ "'
mv "$T/x/pass" "$T/x/pass.off"; o=$($M exec "$T/x" r -- echo hi 2>&1); mv "$T/x/pass.off" "$T/x/pass"
ok "没有 sh 通行证: 被拒" 'echo "$o" | grep -q "^── r  ✘ " && ! echo "$o" | grep -qx "hi"'

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 12 "$T"/*.log; }
[ $fail -eq 0 ]
