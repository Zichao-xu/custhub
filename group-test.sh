#!/usr/bin/env bash
# 本机谁能用(design-v3 §0 第 19 条): 要 root + 能建账号, 只在 Linux 容器里跑(linux-test.sh 带上它)
#   装成系统安装的样子(/opt/custhub/custhub run /opt/custhub/node), 守护起来时补上 custhub 组、权限、PATH
#   1 不在组里的账号: 提示怎么加; 读不了钥匙
#   2 root 用 custhub user add 加进组 → 新登录的会话不用 sudo 就能 ls / pass / code; 照样读不了钥匙
#   3 user del 移出 → 又用不了
#   4 能 sudo 的账号跑要 root 的命令(user add): 自动换成 sudo
set -uo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] && [ "$(uname)" = Linux ] || { echo "group-test 要在 Linux 上用 root 跑(./linux-test.sh group-test)"; exit 0; }
./build.sh >/dev/null || exit 1
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
T=$(mktemp -d); DP=
trap 'kill $DP $SSH_AGENT_PID 2>/dev/null; rm -rf "$T" /opt/custhub /usr/local/bin/custhub' EXIT
for u in eng1 eng2 eng3; do id $u >/dev/null 2>&1 || useradd -m -s /bin/bash $u; done
command -v sudo >/dev/null && echo "eng2 ALL=(root) NOPASSWD: ALL" >/etc/sudoers.d/eng2
as(){ local u=$1; shift; su - "$u" -c "$*" 2>&1; }

eval "$(ssh-agent -s)" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"; ssh-add -q "$T/master" 2>/dev/null
mkdir -p /opt/custhub/node; cp mesh /opt/custhub/custhub; chmod 700 /opt/custhub
NP=$(/opt/custhub/custhub keygen /opt/custhub/node)
{ echo "custhub-mesh-trust 1"; echo "node box $NP"; echo "--end--"; } >"$T/d"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d" 2>/dev/null; cat "$T/d" "$T/d.sig" >/opt/custhub/node/trust
printf 'master %s\nctl 127.0.0.1:7481\nrelay off\nupnp off\nlog /opt/custhub/node/mesh.log\n' "$(cut -d' ' -f1,2 "$T/master.pub")" >/opt/custhub/node/conf
/opt/custhub/custhub run /opt/custhub/node >/dev/null 2>&1 & DP=$!
for _ in $(seq 40); do [ -s /opt/custhub/node/ctl.token ] && break; sleep 0.25; done
/opt/custhub/custhub key --dir /opt/custhub/node pass --to box >/dev/null 2>&1

echo "== 0 守护起来时补上组、权限、PATH"
getent group custhub >/dev/null && ok "建了 custhub 组" || ng "没有 custhub 组"
m(){ stat -c '%a %G' "$1"; }
[ "$(m /opt/custhub)" = "755 root" ] && [ "$(m /opt/custhub/node)" = "710 custhub" ] && [ "$(m /opt/custhub/node/conf)" = "640 custhub" ] && [ "$(m /opt/custhub/node/ctl.token)" = "640 custhub" ] && [ "$(stat -c %a /opt/custhub/node/node.key)" = 600 ] \
  && ok "安装目录 755; 节点目录 710、conf / 令牌 640 给 custhub 组; 钥匙 600 只给 root" || ng "权限: $(m /opt/custhub) / $(m /opt/custhub/node) / $(m /opt/custhub/node/conf) / $(m /opt/custhub/node/ctl.token) / $(stat -c %a /opt/custhub/node/node.key)"
[ "$(readlink /usr/local/bin/custhub)" = /opt/custhub/custhub ] && ok "custhub 在 PATH 里" || ng "PATH 链接: $(ls -l /usr/local/bin/custhub 2>&1)"

echo "== 1 不在组里"
o=$(as eng1 custhub version); echo "$o" | grep -q "^custhub " && ok "谁都能跑 custhub version" || ng "version: $o"
o=$(as eng1 custhub ls); echo "$o" | grep -q "账号 eng1 不在 custhub 组里" && echo "$o" | grep -q "sudo custhub user add eng1" && ok "不在组里: 说清楚怎么加" || ng "提示: $o"

echo "== 2 加进组"
o=$(custhub user add eng1); echo "$o" | grep -q "eng1 加进了 custhub 组" && ok "root: custhub user add eng1" || ng "user add: $o"
o=$(custhub user ls); echo "$o" | grep -q "eng1" && ok "user ls 列出 eng1" || ng "user ls: $o"
o=$(as eng1 custhub ls); echo "$o" | grep -q "^本机 box" && ok "eng1 不用 sudo: custhub ls" || ng "eng1 ls: $o"
o=$(as eng1 custhub pass); echo "$o" | grep -q "进 box, 用 sh" && ok "eng1 不用 sudo: custhub pass 列出本机通行证" || ng "eng1 pass: $o"
o=$(as eng1 custhub code); echo "$o" | grep -qE '^[0-9A-Z]{3}-[0-9A-Z]{3}$' && ok "eng1 不用 sudo: custhub code(问守护)" || ng "eng1 code: $o"
o=$(as eng1 cat /opt/custhub/node/node.key); echo "$o" | grep -qi "permission denied" && ok "eng1 照样读不了节点钥匙" || ng "钥匙: $o"
o=$(as eng1 ls /opt/custhub/node); echo "$o" | grep -qi "permission denied" && ok "eng1 列不了节点目录(只能按名字进)" || ng "列目录: $o"
/opt/custhub/custhub key --dir /opt/custhub/node pass --for box --to box --out "$T/p2" >/dev/null 2>&1; cp "$T/p2" /tmp/p2; chmod 644 /tmp/p2
o=$(as eng1 custhub pass /tmp/p2); echo "$o" | grep -q "已装上: 进 box" && ok "eng1 不用 sudo: custhub pass <文件> 装上(守护代存)" || ng "eng1 装证: $o"

echo "== 3 移出组"
custhub user del eng1 >/dev/null
o=$(as eng1 custhub ls); echo "$o" | grep -q "不在 custhub 组里" && ok "user del 后又用不了" || ng "移出后: $o"

echo "== 4 能 sudo 的账号: 要 root 的命令自动 sudo"
if command -v sudo >/dev/null; then
  o=$(as eng2 custhub user add eng3); echo "$o" | grep -q "eng3 加进了 custhub 组" && ok "eng2 跑 custhub user add: 自动换成 sudo" || ng "自动 sudo: $o"
else ng "容器里没有 sudo"; fi
o=$(as eng1 custhub user add eng1 </dev/null); echo "$o" | grep -qE "要 root|sudo: .*password" && ! id -nG eng1 | grep -qw custhub && ok "不能免密 sudo 的账号: 交给 sudo 问密码(这里没终端, 问不了就不加)" || ng "不能 sudo: $o"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
