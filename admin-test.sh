#!/usr/bin/env bash
# 管理端验收(design-v3 §0 第 18 条): custhub key, 测试口令 + 临时 ssh-agent
#   1 解锁: 口令错(推出的主公钥对不上)不放; 对了放进 agent 带有效期, 和 passkey.py 推出的一样
#   2 待批准(带接入码) → 按接入码批准 → 节点接入; ls; 移除 → 节点被踢
#   3 种子、发布清单、通行证都用 agent 里的主钥匙签, ssh-keygen 认
#   4 上锁后签不了
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) ${SSH_AGENT_PID:-} 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=$((20000 + RANDOM % 20000)); PR=$base
PH="umbra quill tundra jasper mosaic ripple falcon ember cobalt meadow lantern pivot"
eval "$(ssh-agent -s)" >/dev/null
CUSTHUB_PASSPHRASE="$PH" $M masterpub >"$T/master.pub"
K(){ $M key --dir "$T/adm" "$@"; }

for n in r adm x y z; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
i=0; for n in r adm x y z; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s/%s.log\nupnp off\nhello host-%s\n' "$(cut -d' ' -f1,2 "$T/master.pub")" $((base+10+i)) "$T" "$n" "$n" >"$T/$n/conf"
  [ $n = r ] || echo "relay off" >>"$T/$n/conf"
done

echo "== 1 解锁"
K status >/dev/null 2>&1 && ng "还没解锁就说已解锁" || ok "没解锁时 status 是未解锁"
o=$(CUSTHUB_PASSPHRASE="wrong words here alpha beta gamma delta epsilon zeta" K unlock 2>&1); echo "$o" | grep -q "主公钥和本机名单的主公钥不一样" && ok "口令不对: 推出的主公钥对不上, 不放进去" || ng "错口令: $o"
CUSTHUB_PASSPHRASE="$PH" K unlock 1 >/dev/null 2>&1 && K status | grep -q "^已解锁" && ok "口令对: 放进 ssh-agent, status 已解锁" || ng "解锁失败"
# 对照: 参考实现 passkey.py(私有仓库里有就现算), 没有就用它预先算好的值(同一个测试口令)
REF=AAAAC3NzaC1lZDI1NTE5AAAAIGaN8mo46ha4VuLUZZB0GnCbI8wIk/98acXuXNQlBHCI
[ -f ../../passkey.py ] && REF=$(CUSTHUB_PASSPHRASE="$PH" python3 ../../passkey.py pub | cut -d' ' -f2)
ssh-add -L | grep -q "custhub-master$" && [ "$(ssh-add -L | grep custhub-master$ | cut -d' ' -f2)" = "$REF" ] && ok "agent 里的主钥匙和参考实现推出的一样(注释 custhub-master)" || ng "agent: $(ssh-add -L)"
# 初始名单 v1 用 agent 里的主钥匙签(ssh-keygen 认 agent 里的钥匙)
{ echo "custhub-mesh-trust 1"; echo "relay r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node adm $(cat "$T/adm.pub")"; echo "--end--"; } >"$T/d1"
ssh-keygen -q -Y sign -f "$T/master.pub" -n custhub-mesh-trust "$T/d1" 2>/dev/null && cat "$T/d1" "$T/d1.sig" >"$T/t1" || ng "ssh-keygen 用 agent 签不了"
for n in r adm x y z; do cp "$T/t1" "$T/$n/trust"; done
for n in r adm x y z; do CUSTHUB_MESH_PENDING_S=2 $M run "$T/$n" 2>/dev/null & done
wait_for 15 sh -c "$M ls $T/adm | grep -qE '^  r .* 通$'"

echo "== 2 批准 / 移除"
code=$($M code "$T/x")
wait_for 15 grep -qF "$(cat "$T/x.pub")" "$T/r/pending"
o=$(K pending)
echo "$o" | grep -q "^  $code  $(cat "$T/x.pub")" && ok "pending 列出 x, 带接入码 $code" || ng "pending: $o"
o=$(K approve "$(echo "$code" | tr 'A-Z' 'a-z' | tr -d -)" x1 2>&1); echo "$o" | grep -q "已批准 x1" && ok "按接入码批准(小写、不带横线也认): $(echo "$o" | tail -1)" || ng "approve: $o"
wait_for 20 grep -q "已被批准" "$T/x.log"
grep -q "已被批准(名单 v2 里有本机, 名字 x1)" "$T/x.log" && ok "x 收到 v2, 知道自己叫 x1" || ng "x 日志: $(grep 名单 "$T/x.log" | tail -2)"
K ls | grep -q "^  x1 .*$code" && ok "ls 里有 x1" || ng "ls: $(K ls)"
o=$(K approve "$code" x2 2>&1); echo "$o" | grep -q "待批准里没有" && ok "已批准的不会再出现在待批准里" || ng "重复批准: $o"
K remove x1 >/dev/null 2>&1
wait_for 15 grep -q "名单 v2 → v3" "$T/x.log"
! K ls | grep -q "x1" && ok "移除 x1: 名单 v3 里没有了" || ng "移除后 ls: $(K ls)"

echo "== 2b 自动编号 / 机器名备注 / 改名"
cy=$($M code "$T/y"); cz=$($M code "$T/z")
wait_for 15 sh -c "$M key --dir $T/adm pending | grep -q $cz"
o=$(K approve "$cy" 2>&1); echo "$o" | grep -q "已批准 A-1(接入码 $cy, 机器名 host-y)" && ok "不写名字: 自动编号 A-1, 机器名 host-y 记进备注" || ng "自动编号: $o"
K ls | grep -qE "^  A-1 +$cy  host-y " && ok "key ls 有机器名一列" || ng "ls: $(K ls)"
grep -q "^node A-1 $(cat "$T/y.pub") host=host-y$" <(K ls >/dev/null; $M ctl "$T/adm" TRUST) && ok "名单行: node A-1 <公钥> host=host-y" || ng "名单: $($M ctl "$T/adm" TRUST | grep A-1)"
o=$(K rename A-1 yy 2>&1); echo "$o" | grep -q "A-1 改名为 yy" && K ls | grep -qE "^  yy +$cy  host-y " && ok "rename: 改名, 机器名备注跟着" || ng "rename: $o / $(K ls)"
wait_for 15 grep -qE "本机改名: A-1 → yy|名字 yy" "$T/y.log"
grep -qE "本机改名: A-1 → yy|名字 yy" "$T/y.log" && ok "y 不用重启就知道自己改叫 yy 了" || ng "y 日志: $(grep 名单 "$T/y.log" | tail -2)"
o=$(K approve "$cz" 2>&1); echo "$o" | grep -q "已批准 A-2" && ok "A-1 改名后不再复用: 下一台是 A-2" || ng "号复用了: $o"

echo "== 3 种子 / 发布清单 / 通行证"
K seed --github example/repo --out "$T/seed" 2>/dev/null
head -3 "$T/seed" | grep -q "^master $(cut -d' ' -f1,2 "$T/master.pub") custhub-master$" && grep -q "^github example/repo$" "$T/seed" && grep -qE "^custhub-mesh-trust (6|7)$" "$T/seed" && ok "种子: 主公钥 + 仓库 + 当前名单" || ng "种子: $(head -5 "$T/seed")"
cp "$M" "$T/custhub3-0.0.9-t1"
K release 0.0.9 "$T/custhub3-0.0.9-t1" --only "adm" --out "$T/custhub3.release" 2>/dev/null
sed '/^--end--$/q' "$T/custhub3.release" >"$T/rb"; sed -n '/BEGIN SSH SIGNATURE/,$p' "$T/custhub3.release" >"$T/rb.sig"
echo "master $(cut -d' ' -f1,2 "$T/master.pub")" >"$T/allowed"
ssh-keygen -Y verify -f "$T/allowed" -I master -n custhub-rel -s "$T/rb.sig" <"$T/rb" >/dev/null 2>&1 && grep -q "^file t1 $(wc -c <"$M" | tr -d ' ') $(shasum -a 512 "$M" | cut -d' ' -f1)$" "$T/rb" && grep -q "^only adm$" "$T/rb" && ok "发布清单: 大小 + sha512 + 灰度, ssh-keygen 认签名" || ng "清单: $(cat "$T/rb")"
K pass --for "$(cat "$T/x.pub")" --to adm --svc sh --out "$T/px" 2>/dev/null && $M passcheck "$T/px" "$T/master.pub" "$(cat "$T/x.pub")" "$(cat "$T/adm.pub")" sh "$(date +%s)" | grep -q ok && ok "key pass 签通行证" || ng "key pass 失败"

echo "== 4 上锁"
K lock | grep -q "已上锁" && ! ssh-add -L 2>/dev/null | grep -q custhub-master && ok "上锁: agent 里没有主钥匙了" || ng "上锁: $(ssh-add -L 2>&1)"
o=$(K remove adm 2>&1); echo "$o" | grep -q "ssh-agent 里没有主钥匙" && ok "上锁后改不了名单" || ng "上锁后: $o"

echo "== 5 第一次建网(还没有节点)"
ssh-add -D >/dev/null 2>&1
mkdir -p "$T/fresh"
o=$(CUSTHUB_PASSPHRASE="$PH" $M key --dir "$T/fresh" unlock 1 2>&1)
echo "$o" | grep -qF "主公钥(还没有节点, 没比对): $(cut -d' ' -f1,2 "$T/master.pub") custhub-master" && ok "没有节点也能解锁, 打印推出的主公钥" || ng "unlock: $o"
mkdir -p "$T/g1"; $M keygen "$T/g1" >"$T/g1.pub"
printf 'custhub-mesh-trust 1\nrelay seed1 %s 127.0.0.1:%s\nnode boss %s\n--end--\n' "$(cat "$T/r.pub")" $PR "$(cat "$T/g1.pub")" >"$T/body"
$M key --dir "$T/fresh" sign-trust "$T/body" --master "$(cut -d' ' -f1,2 "$T/master.pub")" --out "$T/gtrust" 2>/dev/null && head -1 "$T/gtrust" | grep -q "custhub-mesh-trust 1" && ok "sign-trust: 签第一份名单" || ng "sign-trust 失败"
$M key --dir "$T/fresh" seed --trust "$T/gtrust" --master "$(cut -d' ' -f1,2 "$T/master.pub")" --github o/r --out "$T/gseed" 2>/dev/null && grep -q "^relay seed1 " "$T/gseed" && ok "seed --trust: 从名单出种子" || ng "seed 失败"
o=$(CUSTHUB_CTL=127.0.0.1:$((base+30)) CUSTHUB_HOME=$T/ghome CUSTHUB_SVC_DRY=1 CUSTHUB_SVC_KIND=systemd $M join --seed "$T/gseed" --wait 1 2>&1)
echo "$o" | grep -q "接入码" && ok "拿这份种子能接入" || ng "join: $o"
[ -f "$T/ghome/node/dry/pid" ] && kill "$(cat "$T/ghome/node/dry/pid")" 2>/dev/null

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
