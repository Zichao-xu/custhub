#!/usr/bin/env bash
# 给人和 AI 用的: inventory / exec(多台并行) / netcheck 和 log 看别的机器 / 各命令 --json / watch 事件 / wait 等条件
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); eval "$(ssh-agent -s)" >/dev/null   # 自己的空 agent: 守护继承它, 不碰真的主钥匙
trap 'kill $SSH_AGENT_PID $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ if eval "$2"; then pass=$((pass+1)); echo "  ✔ $1"; else fail=$((fail+1)); echo "  ✘ $1"; fi; }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}; PR=$base PX=$((base+1)) PY=$((base+2))
export CUSTHUB_MESH_OBS_S=3600 CUSTHUB_IP6= CUSTHUB_ONLINE_S=25

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
mkdir -p "$T/px"; mv "$T"/x/pass* "$T/px/"; ssh-add -q "$T/master" 2>/dev/null
o=$($M exec "$T/x" r -- echo hi 2>&1)
ok "主钥匙解锁着、没有通行证: 自动给本机签一张, 照样跑成" 'echo "$o" | grep -qx "hi" && grep -q "自动给本机签了一张" "$T/x.log" && grep -q "^to all$" "$T/x/pass"'
ssh-add -q -D 2>/dev/null; rm -f "$T"/x/pass*
o=$($M exec "$T/x" r -- echo hi 2>&1)
ok "上锁后、没有通行证: 不自动签, 被拒" 'echo "$o" | grep -q "^── r  ✘ " && [ ! -e "$T/x/pass" ]'
mv "$T"/px/pass* "$T/x/"

echo "== 4 远程只读查看 / 功能协商 / 各命令的 --json"
ok "netcheck r: 看别的机器的网络状况" '$M netcheck "$T/x" r | grep -q "^TCP 入站: "'
ok "netcheck r --json 合法, 有入站和直连" '$M netcheck "$T/x" r --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"name\"]==\"r\" and \"tcp_in\" in d and isinstance(d[\"links\"],list)"'
o=$($M log "$T/x" r --grep 链路建立 --lines 2)
ok "log r --grep --lines: 只要含关键字的最后几行" '[ "$(echo "$o" | grep -c .)" -le 2 ] && [ "$(echo "$o" | grep -c 链路建立)" = "$(echo "$o" | grep -c .)" ] && [ -n "$o" ]'
ok "log(本机)" '$M log "$T/x" --lines 3 | grep -q "\[x\]"'
ok "ping --json 合法, 标出走哪条" '$M ping "$T/x" r --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"route\"]==\"direct\" and any(l[\"chosen\"] for l in d[\"links\"])"'
ok "inventory 里有每台报的功能(含 file、info)" '$M inventory "$T/x" --json | python3 -c "import json,sys; a=json.load(sys.stdin); r=[m for m in a if m[\"name\"]==\"r\"][0]; assert \"file\" in r[\"features\"] and \"info\" in r[\"features\"]"'
head -c 100000 /dev/urandom >"$T/s.bin"
ok "send --json: 一行结果, ok / bytes" '$M send "$T/x" "$T/s.bin" r "$T/s2.bin" --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"ok\"] and d[\"bytes\"]==100000 and d[\"error\"] is None"'
ok "send --json 失败时: ok=false, error 写原因" '{ $M send "$T/x" "$T/nope.bin" r "$T/s3.bin" --json; true; } | python3 -X utf8 -c "import json,sys; d=json.load(sys.stdin); assert not d[\"ok\"] and \"没有这个文件\" in d[\"error\"]"'

echo "== 5 事件 / 等待"
$M watch "$T/x" --json >"$T/ev" 2>&1 & wp=$!
ok "wait r online: 立刻成立" '$M wait "$T/x" r online --timeout 5'
ok "wait r version 99.0 --timeout 2: 超时返回 4" '$M wait "$T/x" r version 99.0 --timeout 2 2>/dev/null; [ $? = 4 ]'
kill $(pgrep -f "$M run $T/y") 2>/dev/null
ok "y 关掉后 wait y offline 等得到" '$M wait "$T/x" y offline --timeout 60'
wait_for 10 grep -q '"name":"y","type":"offline"' "$T/ev"
ok "watch --json 收到 y 的 offline 事件" 'grep -q "\"name\":\"y\",\"type\":\"offline\"" "$T/ev"'
kill $wp 2>/dev/null

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail -eq 0 ] || { KEEP=1; tail -n 12 "$T"/*.log; }
[ $fail -eq 0 ]
