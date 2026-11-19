#!/usr/bin/env bash
# 通行证模块单独验收(design-v3 §0 第 11 条): 不起网络
#   验: 喂 mesh passcheck 各种真的、假的、过期的通行证
#   签: mesh pass 问临时 ssh-agent 要主钥匙签名, 签出来的 ssh-keygen 和通行证模块都要认
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); DP=; trap 'kill $DP 2>/dev/null; rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
ssh-keygen -q -t ed25519 -N '' -C other  -f "$T/other"
for n in eng a b; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
ENG=$(cat "$T/eng.pub") A=$(cat "$T/a.pub") B=$(cat "$T/b.pub")
epoch(){ python3 -c "import calendar,time,sys; print(calendar.timegm(time.strptime(sys.argv[1],'%Y-%m-%dT%H:%M:%SZ')))" "$1"; }
F=2026-11-19T18:00:00Z U=2026-11-19T20:00:00Z
NOW=$(( $(epoch $F) + 600 ))

# mkpass 文件 [签名钥匙] < 正文(到 --end-- 为止)
mkpass(){ cat >"$T/body"; ssh-keygen -q -Y sign -f "${2:-$T/master}" -n custhub-pass "$T/body" 2>/dev/null; cat "$T/body" "$T/body.sig" >"$1"; rm -f "$T/body.sig"; }
body(){  # body key to svc from until [额外行]
  printf 'custhub-pass v1\nkey %s\nto %s\nsvc %s\nfrom %s\nuntil %s\n%s--end--\n' "$1" "$2" "$3" "$4" "$5" "${6:-}"; }
chk(){  # chk 期望(ok|原因片段) 说明 文件 who node svc [now]
  local want=$1 what=$2; shift 2
  local got; got=$($M passcheck "$1" "$T/master.pub" "$2" "$3" "$4" "${5:-$NOW}" 2>&1)
  case $got in *"$want"*) ok "$what: $got" ;; *) ng "$what: 要 $want, 得到 $got" ;; esac
}

body "$ENG" "$A" "sh port:22,3389" $F $U | mkpass "$T/p1"
chk ok              "正常: sh"                          "$T/p1" "$ENG" "$A" sh
chk ok              "正常: 端口在列表里"                "$T/p1" "$ENG" "$A" port:3389
chk ok              "只问能不能进网(不问机器和服务)"    "$T/p1" "$ENG" - -
chk 这项服务        "端口不在列表里"                    "$T/p1" "$ENG" "$A" port:80
chk 这台机器        "机器不在 to 里"                    "$T/p1" "$ENG" "$B" sh
chk 不是发给        "别人拿去用"                        "$T/p1" "$A" "$A" sh
chk 还没生效        "还没到 from(超过 5 分钟容差)"      "$T/p1" "$ENG" "$A" sh $(( $(epoch $F) - 301 ))
chk ok              "早 5 分钟以内算容差"               "$T/p1" "$ENG" "$A" sh $(( $(epoch $F) - 299 ))
chk 已过期          "过了 until(超过 5 分钟容差)"       "$T/p1" "$ENG" "$A" sh $(( $(epoch $U) + 300 ))

body "$ENG" all "port:*" $F $U | mkpass "$T/p2"
chk ok              "to all + port:*"                    "$T/p2" "$ENG" "$B" port:8080
chk 这项服务        "port:* 不含 sh"                     "$T/p2" "$ENG" "$B" sh

body "$ENG" "$A" sh $F $U | mkpass "$T/p3" "$T/other"
chk 签名不对        "不是主钥匙签的"                    "$T/p3" "$ENG" "$A" sh

sed 's/^svc sh$/svc sh port:*/' "$T/p3" >/dev/null
body "$ENG" "$A" sh $F $U | mkpass "$T/p4"
sed 's/^to .*/to all/' "$T/p4" >"$T/p4x"
chk 签名不对        "签完再改 to"                       "$T/p4x" "$ENG" "$B" sh

body "$ENG" "$A" sh 2026-11-19T00:00:00Z 2026-11-20T00:00:01Z | mkpass "$T/p5"
chk 超过\ 1\ 天     "有效期超过 1 天"                   "$T/p5" "$ENG" "$A" sh $(epoch 2026-11-19T01:00:00Z)

body "$ENG" "$A" sh $U $F | mkpass "$T/p6"
chk 有效期不对      "until 早于 from"                    "$T/p6" "$ENG" "$A" sh

body "$ENG" "$A" sh 2026-11-19 $U | mkpass "$T/p7"
chk 有效期不对      "时间格式不对"                      "$T/p7" "$ENG" "$A" sh

body "$ENG" "$A" sh $F $U "via something
" | mkpass "$T/p8"
chk 委派            "带 via(委派)还不支持"              "$T/p8" "$ENG" "$A" sh

body "$ENG" "$A" sh $F $U "role admin
" | mkpass "$T/p9"
chk 不认识的行      "有不认识的行"                      "$T/p9" "$ENG" "$A" sh

printf 'custhub-pass v1\nkey %s\nto %s\nfrom %s\nuntil %s\n--end--\n' "$ENG" "$A" $F $U | mkpass "$T/p10"
chk 没有\ svc       "缺 svc"                            "$T/p10" "$ENG" "$A" sh

head -c 100 "$T/p1" >"$T/p11"
chk 不完整          "截断"                              "$T/p11" "$ENG" "$A" sh

echo "== 签发(mesh pass)"
eval "$(ssh-agent -s)" >/dev/null; trap 'kill $SSH_AGENT_PID $DP 2>/dev/null; rm -rf "$T"' EXIT
D=$T/eng
{ echo "custhub-mesh-trust 1"; echo "node a $A"; echo "node b $B"; echo "node eng $ENG"; echo "--end--"; } >"$T/tdata"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/tdata" 2>/dev/null; cat "$T/tdata" "$T/tdata.sig" >"$D/trust"
printf 'master %s\nctl 127.0.0.1:1\n' "$(cat "$T/master.pub")" >"$D/conf"
NOWR=$(date +%s)
o=$($M key --dir "$D" pass --to a --svc sh 2>&1); echo "$o" | grep -q "没有主钥匙" && ok "agent 里没主钥匙: 签不了($o)" || ng "没主钥匙也签了: $o"
ssh-add -q "$T/other" 2>/dev/null
o=$($M key --dir "$D" pass --to a --svc sh 2>&1); echo "$o" | grep -q "没有主钥匙" && ok "agent 里只有别的钥匙: 签不了" || ng "拿别的钥匙签了: $o"
ssh-add -q "$T/master" 2>/dev/null
$M key --dir "$D" pass --to a,b --svc "sh port:22" 2>"$T/err" && [ -s "$D/pass" ] && ok "不写 --for: 发给本机, 写进 目录/pass($(cat "$T/err"))" || ng "签发失败: $(cat "$T/err")"
chk ok   "签出来的通行证模块认: 进 b 用 sh"   "$D/pass" "$ENG" "$B" sh $NOWR
chk 这项服务 "签出来的: svc 照写(不含 3389)" "$D/pass" "$ENG" "$A" port:3389 $NOWR
chk 已过期 "签出来的: 默认 2 小时"            "$D/pass" "$ENG" "$A" sh $((NOWR + 7200 + 301))
sed '/^--end--$/q' "$D/pass" >"$T/pbody"; sed -n '/BEGIN SSH SIGNATURE/,$p' "$D/pass" >"$T/pbody.sig"
echo "master $(cut -d' ' -f1,2 "$T/master.pub")" >"$T/allowed"
ssh-keygen -Y verify -f "$T/allowed" -I master -n custhub-pass -s "$T/pbody.sig" <"$T/pbody" >/dev/null 2>&1 && ok "ssh-keygen -Y verify 也认(格式兼容)" || ng "ssh-keygen 不认签出来的通行证"
$M key --dir "$D" pass --for "$A" --to b --svc "port:*" --hours 0.5 --out - >"$T/pa" 2>/dev/null && chk ok "--for 别人(公钥): 打印到标准输出" "$T/pa" "$A" "$B" port:80 $NOWR || ng "--for 签发失败"
chk 已过期 "--hours 0.5 生效"                 "$T/pa" "$A" "$B" port:80 $((NOWR + 1800 + 301))
mkdir -p "$T/g0"; G=$($M keygen "$T/g0")
$M key --dir "$D" pass --for "$G" --to a --svc sh --out "$T/pg" 2>/dev/null && chk ok "--for 名单外的公钥(访客)" "$T/pg" "$G" "$A" sh $NOWR || ng "给访客签发失败"
o=$($M key --dir "$D" pass --to a --svc sh --hours 25 2>&1);  echo "$o" | grep -q "最长 1 天" && ok "--hours 25 被拒" || ng "--hours 25 没拒: $o"
o=$($M key --dir "$D" pass --to nobody --svc sh 2>&1);       echo "$o" | grep -q "名单里没有这台" && ok "--to 名单外的机器被拒" || ng "--to 名单外没拒: $o"
o=$($M key --dir "$D" pass --to a --svc "ssh" 2>&1);         echo "$o" | grep -q "svc 不对" && ok "--svc 写错被拒" || ng "--svc 写错没拒: $o"

echo "== 本机存几张、custhub pass 装上 / 列出"
CB=$((20000 + RANDOM % 20000))   # custhub pass 经本机守护: 给 eng、a 起守护(不开监听、没有可达节点, 只为控制口)
printf 'master %s\nctl 127.0.0.1:%s\nrelay off\nupnp off\nlog %s/eng.log\n' "$(cat "$T/master.pub")" $CB "$T" >"$D/conf"
$M run "$D" >/dev/null 2>&1 & DP="$DP $!"
$M key --dir "$D" pass --to b --svc "port:22" 2>/dev/null
[ -s "$D/pass" ] && [ -s "$D/pass.1" ] && ok "再签一张不同范围的: 并存(pass、pass.1), 不顶掉前一张" || ng "存放: $(ls "$D")"
$M key --dir "$D" pass --to b --svc "port:22" --hours 3 2>/dev/null
[ ! -e "$D/pass.2" ] && ok "同范围再签: 替换原来那张, 不多占位置" || ng "多占了: $(ls "$D")"
o=$($M pass --dir "$D"); echo "$o" | grep -q "进 a,b, 用 sh port:22, 还剩 [12] 小时" && echo "$o" | grep -q "进 b, 用 port:22, 还剩 [23] 小时" && ok "custhub pass 列出两张、剩多久" || ng "列出: $(echo "$o" | tr "\n" "|")"
(cd "$T" && $M key --dir "$D" pass --for a --to b 2>"$T/err") && [ -s "$T/a.pass" ] && grep -q "custhub pass a.pass" "$T/err" && ok "--for 名字: 存成 a.pass(默认 sh), 提示对方怎么装" || ng "--for a: $(cat "$T/err"); $(ls "$T")"
cp "$D/trust" "$T/a/trust"; printf 'master %s\nctl 127.0.0.1:%s\nrelay off\nupnp off\nlog %s/a.log\n' "$(cat "$T/master.pub")" $((CB+1)) "$T" >"$T/a/conf"
$M run "$T/a" >/dev/null 2>&1 & DP="$DP $!"
for _ in $(seq 20); do [ -s "$T/a/ctl.token" ] && [ -s "$D/ctl.token" ] && break; sleep 0.25; done
o=$($M pass --dir "$T/a" "$T/a.pass"); echo "$o" | grep -q "已装上: 进 b, 用 sh" && echo "$o" | grep -q "现在可以: custhub sh b" && [ -s "$T/a/pass" ] && ok "custhub pass a.pass: 装上, 告诉下一步" || ng "装: $o"
o=$($M pass --dir "$T/a" "$D/pass" 2>&1); echo "$o" | grep -q "不是发给本机的" && ok "别人的通行证装不上" || ng "装别人的: $o"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
