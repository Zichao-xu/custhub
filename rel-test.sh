#!/usr/bin/env bash
# 发布物 + 自升级验收(design-v3 §0 第 15 条), 本机多进程 + python 假 GitHub
#   每个节点跑自己的一份程序副本(换上新版互不影响); 新旧版本都是真构建出来的(VER / PLAT)
#   1 有 GitHub 的 r、a 自己拉到新版, 换上、转正
#   2 没有 GitHub 的 b 从网内取(断点续传的 pkg 服务), 换上
#   3 每台都缓存最新版全部发布物(别的平台、接入脚本); 只读 HTTP 发清单、程序、接入脚本、种子
#   4 灰度: only a 的版本 a 升、b 不升
#   5 清单里 sha512 不对: 谁都不升
#   6 回滚: 换上后试用期内连不上网络 → 换回旧版
set -uo pipefail
cd "$(dirname "$0")"
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}; PR=$base GH=$((base+1))
mkdir -p "$T/gh"
for v in 0.0.1 0.0.2 0.0.3 0.0.5; do OUT=$T/m-$v-t1 VER=$v PLAT=t1 ./build.sh >/dev/null || exit 1; done
OUT=$T/m-0.0.2-t2 VER=0.0.2 PLAT=t2 ./build.sh >/dev/null || exit 1
M=$T/m-0.0.1-t1
(cd "$T/gh" && exec python3 -m http.server "$GH" --bind 127.0.0.1) >/dev/null 2>&1 &

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r a b; do mkdir -p "$T/$n" "$T/bin-$n"; cp "$M" "$T/bin-$n/mesh"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "relay r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node a $(cat "$T/a.pub")"; echo "node b $(cat "$T/b.pub")"; echo "--end--"; } >"$T/data"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/data" 2>/dev/null; cat "$T/data" "$T/data.sig" >"$T/trust"
i=0; for n in r a b; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s\nupnp off\nname %s\n' "$(cat "$T/master.pub")" $((base+10+i)) "$T/$n.log" "$n" >"$T/$n/conf"; cp "$T/trust" "$T/$n/trust"
  [ $n = r ] && echo "github o/r" >>"$T/$n/conf"
  [ $n = r ] || echo "relay off" >>"$T/$n/conf"
done
publish(){  # publish 版本 [only 行] [坏 sha]: 写清单 + 附件到假 GitHub
  local v=$1 only=${2:-} badsha=${3:-}
  { echo "custhub-rel v1"; echo "version $v"; echo "signed $(date +%s)"; [ -n "$only" ] && echo "only $only"
    printf 'BASE=${CUSTHUB_BASE:-https://github.com/o/r/releases}\n' >"$T/m-$v-join.sh"
    for p in t1 t2 join.sh; do f=$T/m-$v-$p; [ -f "$f" ] || continue; cp "$f" "$T/gh/custhub3-$v-$p"
      s=$(shasum -a 512 "$f" | cut -d' ' -f1); [ -n "$badsha" ] && [ $p = t1 ] && s=$(printf '%0128d' 0)
      echo "file $p $(wc -c <"$f" | tr -d ' ') $s"; done
    echo "--end--"; } >"$T/rel"
  rm -f "$T/rel.sig"; ssh-keygen -q -Y sign -f "$T/master" -n custhub-rel "$T/rel" 2>/dev/null; cat "$T/rel" "$T/rel.sig" >"$T/gh/custhub3.release.tmp"; mv "$T/gh/custhub3.release.tmp" "$T/gh/custhub3.release"
}
export CUSTHUB_REL_FIRST_S=1 CUSTHUB_REL_CHECK_S=2 CUSTHUB_REL_TRIAL_S=8
start(){ local u=http://127.0.0.1:$GH/; [ $1 = b ] && u=http://127.0.0.1:1/; CUSTHUB_REL_URL=$u "$T/bin-$1/mesh" run "$T/$1" 2>/dev/null & eval "PID_$1=$!"; }
ver(){ "$T/bin-$1/mesh" version | awk '{print $2}'; }
for n in r a b; do start $n; done
up(){ $M ls "$T/$1" | grep -qE "^  r .* 通$"; }
wait_for 15 up a; wait_for 15 up b

echo "== 1 有 GitHub 的自己拉"
publish 0.0.2
wait_for 30 sh -c "[ \"\$($T/bin-a/mesh version | awk '{print \$2}')\" = 0.0.2 ] && grep -q '0.0.2 转正' $T/a.log && grep -q '0.0.2 转正' $T/r.log"
[ "$(ver a)" = 0.0.2 ] && [ "$(ver r)" = 0.0.2 ] && ok "r、a 自己从 GitHub 拉到 0.0.2 并换上" || ng "r=$(ver r) a=$(ver a)"
grep -q "0.0.2 转正(已连上网络)" "$T/a.log" && ok "a 换上后连上网络, 转正" || ng "a 没转正"
[ ! -f "$T/bin-a/mesh.old" ] && ok "转正后旧版 .old 删掉(只留最新版)" || ng ".old 还在"

echo "== 2 没有 GitHub 的 b 从网内取"
wait_for 30 sh -c "[ \"\$($T/bin-b/mesh version | awk '{print \$2}')\" = 0.0.2 ]"
[ "$(ver b)" = 0.0.2 ] && ok "b 升到 0.0.2" || ng "b=$(ver b)"
grep -q "取 custhub3-0.0.2-t1: 问 [ra]" "$T/b.log" && ! grep -q "取 custhub3-0.0.2-t1: http" "$T/b.log" && ok "b 的包是从网内的成员那里取的" || ng "b 取包: $(grep '取 custhub3-0.0.2-t1' "$T/b.log" | head -3)"
grep -q "开本机 pkg:custhub3-0.0.2-t1" "$T/r.log" "$T/a.log" 2>/dev/null || grep -q "凭通行证开本机 pkg\|开本机 pkg" "$T"/*.log; ok "取包不用通行证(b 没有通行证)"

echo "== 3 每台都缓存最新版的全部发布物; 只读 HTTP"
wait_for 15 test -f "$T/r/rel-custhub3-0.0.2-t2"; wait_for 15 test -f "$T/a/rel-custhub3-0.0.2-join.sh"; wait_for 20 test -f "$T/b/rel-custhub3-0.0.2-join.sh"
[ -f "$T/r/rel-custhub3-0.0.2-t2" ] && [ -f "$T/a/rel-custhub3-0.0.2-t2" ] && [ -f "$T/b/rel-custhub3-0.0.2-join.sh" ] && ok "r、a、b 都缓存了别的平台和接入脚本" || ng "缓存: $(ls "$T"/?/rel-* | tr '\n' ' ')"
H=http://127.0.0.1:$PR
curl -fsS "$H/releases/latest/download/custhub3.release" -o "$T/h.rel" && cmp -s "$T/h.rel" "$T/r/rel.release" && ok "HTTP: 发布清单" || ng "HTTP 清单"
curl -fsS "$H/releases/download/v0.0.2/custhub3-0.0.2-t2" -o "$T/h.t2" && cmp -s "$T/h.t2" "$T/m-0.0.2-t2" && ok "HTTP: 别的平台的程序, 内容一致" || ng "HTTP 程序"
o=$(curl -fsS "$H/sh"); [ "$o" = "BASE=\${CUSTHUB_BASE:-$H/releases}" ] && ok "HTTP: 接入脚本里的 GitHub 地址换成了本机($o)" || ng "HTTP 脚本: [$o]"
curl -fsS "$H/releases/latest/download/custhub3.seed" | head -1 | grep -qx "custhub-seed v1" && curl -fsS "$H/releases/latest/download/custhub3.seed" | grep -q "^custhub-mesh-trust " && ok "HTTP: 按当前名单现出种子" || ng "HTTP 种子"
c=$(curl -s -o /dev/null -w '%{http_code}' "$H/releases/download/v0.0.1/custhub3-0.0.1-t1"); c2=$(curl -s -o /dev/null -w '%{http_code}' "$H/../r/node.key")
[ "$c" = 404 ] && [ "$c2" = 404 ] && ok "HTTP: 不是最新版的、清单外的一律 404" || ng "HTTP 404: $c $c2"
up a && ok "HTTP 之后链路照常" || ng "a 断了"

echo "== 4 灰度"
publish 0.0.3 "a"
wait_for 30 sh -c "[ \"\$($T/bin-a/mesh version | awk '{print \$2}')\" = 0.0.3 ]"
sleep 3
[ "$(ver a)" = 0.0.3 ] && [ "$(ver b)" = 0.0.2 ] && [ "$(ver r)" = 0.0.2 ] && ok "only a: a 升到 0.0.3, r、b 留在 0.0.2" || ng "r=$(ver r) a=$(ver a) b=$(ver b)"
grep -q "0.0.3 是灰度版本, 不含本机" "$T/b.log" && ok "b 知道是灰度、不含自己" || ng "b 日志里没有灰度说明"
wait_for 10 test -f "$T/r/rel-custhub3-0.0.3-t1"
[ ! -f "$T/r/rel-custhub3-0.0.2-t2" ] && [ -f "$T/r/rel-custhub3-0.0.3-t1" ] && ok "清单换到 0.0.3: 0.0.2 的包删掉, 只留最新版" || ng "旧包: $(ls "$T"/r/rel-* | tr '\n' ' ')"

echo "== 5 sha512 不对"
publish 0.0.5 "" bad
sleep 8
[ "$(ver a)" = 0.0.3 ] && [ "$(ver r)" = 0.0.2 ] && ok "清单 sha512 不对: 谁都不升" || ng "r=$(ver r) a=$(ver a)"
grep -q "取 custhub3-0.0.5-t1: 校验没过" "$T/a.log" && ok "a 校验没过, 换来源后放弃" || ng "a 日志: $(grep 0.0.5 "$T/a.log" | head -3)"

echo "== 6 回滚"
kill $PID_r; wait $PID_r 2>/dev/null
rm -f "$T/a/upgrade.bad"
publish 0.0.5
wait_for 40 grep -q "回滚 0.0.5 → 0.0.3" "$T/a.log"
grep -q "试用 0.0.5" "$T/a.log" && ok "a 换上 0.0.5 进入试用" || ng "a 没试用 0.0.5"
grep -q "回滚 0.0.5 → 0.0.3: 试用期内没连上网络" "$T/a.log" && [ "$(ver a)" = 0.0.3 ] && ok "试用期内连不上网络, 回滚到 0.0.3" || ng "回滚: a=$(ver a) $(grep 回滚 "$T/a.log")"
grep -q "^0.0.5 " "$T/a/upgrade.bad" && ok "0.0.5 记进 upgrade.bad" || ng "upgrade.bad: $(cat "$T/a/upgrade.bad" 2>/dev/null)"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
