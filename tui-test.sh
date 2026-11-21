#!/usr/bin/env bash
# 终端界面验收(design-v3 §0 第 20 条): 临时网络(可达节点 r + 管理员 adm + 新机器 x) + 临时 ssh-agent, 伪终端里按键
#   1 列表: r、adm 在, 主钥匙已解锁
#   2 x 报到 → 待批准里出现 → a + 回车(默认名) → 批准
#   3 s 签通行证给本机进 x → Enter 开 shell → 跑命令 → exit 回到列表
#   4 d + y 移出 x
#   5 上锁后管理功能藏起来
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); DP=
trap 'kill $DP ${SSH_AGENT_PID:-} 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}; PR=$base
eval "$(ssh-agent -s)" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C custhub-master -f "$T/master"
for n in r adm x; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
i=0; for n in r adm x; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s/%s.log\nupnp off\nhello host-%s mac-test 0.0.0\n' "$(cut -d' ' -f1,2 "$T/master.pub")" $((base+10+i)) "$T" "$n" "$n" >"$T/$n/conf"
  [ $n = r ] || echo "relay off" >>"$T/$n/conf"
done
{ echo "custhub-mesh-trust 1"; echo "relay r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node adm $(cat "$T/adm.pub")"; echo "--end--"; } >"$T/d1"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d1" 2>/dev/null; cat "$T/d1" "$T/d1.sig" >"$T/t1"
for n in r adm x; do cp "$T/t1" "$T/$n/trust"; done
printf 'listen 127.0.0.1:%s\n' $PR >>"$T/r/conf"
for n in r adm x; do CUSTHUB_MESH_PENDING_S=2 $M run "$T/$n" >/dev/null 2>&1 & DP="$DP $!"; done
ssh-add -q "$T/master" 2>/dev/null
wait_for 20 sh -c "$M ls $T/adm | grep -qE '^  r .* 通$'"
wait_for 20 grep -qF "$(cat "$T/x.pub")" "$T/r/pending"

cat >"$T/drive.py" <<'PY'
import os, pty, sys, time, select, re, struct, fcntl, termios, json
argv = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0: os.execv(argv[0], argv)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
buf = b''
def pump(t):
    global buf
    end = time.time() + t
    while time.time() < end:
        r,_,_ = select.select([fd],[],[],0.05)
        if r:
            try: buf += os.read(fd, 65536)
            except OSError: return
def screen():
    s = buf.decode('utf-8','replace'); i = s.rfind('\x1b[H\x1b[2J'); s = s[i:] if i >= 0 else s
    s = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', s); s = re.sub(r'\x1b\][^\x07]*\x07', '', s)
    return s.replace('\r', '')
def until(pat, t=20):
    end = time.time() + t
    while time.time() < end:
        pump(0.3)
        if re.search(pat, screen()): return True
    return False
out = {}
pump(3)
out['list'] = screen()
# 选中待批准(在最后): 一直按 j
until(r'待批准', 15)
for _ in range(6): os.write(fd, b'j'); pump(0.2)
out['pend'] = screen()
os.write(fd, b'a'); pump(1); os.write(fd, b'\r')
out['approved'] = until(r'已批准 A-1', 20); out['after_approve'] = screen()
until(r'A-1 .*在线', 20)
# 选中 host-x: 回到顶再往下找
for _ in range(6): os.write(fd, b'k'); pump(0.1)
for _ in range(6):
    if re.search(r'> A-1', screen()): break
    os.write(fd, b'j'); pump(0.3)
os.write(fd, b's'); pump(0.5); os.write(fd, b'\r'); pump(0.3); os.write(fd, b'\r'); pump(0.3); os.write(fd, b'\r')
out['signed'] = until(r'通行证签好了', 15); out['after_sign'] = screen()
os.write(fd, b'\r'); pump(3)
os.write(fd, b'echo tui-$((40+2))\r'); pump(2)
s = buf.decode('utf-8','replace'); out['shell'] = 'tui-42' in s
os.write(fd, b'exit\r')
out['back'] = until(r'shell 结束了', 15)
os.write(fd, b'd'); pump(0.5); os.write(fd, b'y\r')
out['removed'] = until(r'移出', 15); out['after_remove'] = screen()
pump(3); out['after_remove2'] = screen()
os.write(fd, b'l'); out['locked'] = until(r'主钥匙: 未解锁', 10); out['after_lock'] = screen()
os.write(fd, b'q'); pump(1)
print(json.dumps(out, ensure_ascii=False))
PY
R=$(python3 "$T/drive.py" "$M" tui "$T/adm"); [ -n "${DEBUG:-}" ] && echo "$R" >"$T/r.json"
j(){ python3 -c 'import json,sys; v=json.loads(sys.argv[1])[sys.argv[2]]; print(v if isinstance(v,str) else ("1" if v else ""))' "$R" "$1"; }

echo "== 1 列表"
s=$(j list); echo "$s" | grep -q "主钥匙: 已解锁" && echo "$s" | grep -qE "^[ >] r +在线" && echo "$s" | grep -q "adm .*本机" && ok "列表: r 在线、adm 本机、主钥匙已解锁" || ng "列表: $s"
echo "== 2 批准"
s=$(j pend); echo "$s" | grep -q "> .*host-x" && ok "待批准里有 host-x(带接入码、机器名)" || ng "待批准: $s"
[ -n "$(j approved)" ] && ok "a + 回车: 自动编号 A-1 批准(机器名 host-x 记进备注)" || ng "批准: $(j after_approve)"
echo "== 3 签证 + shell"
[ -n "$(j signed)" ] && ok "s + 三次回车: 给本机签进 A-1 的通行证(默认 sh、2 小时)" || ng "签证: $(j after_sign)"
[ -n "$(j shell)" ] && ok "Enter 开 shell, 命令在 A-1 上跑了" || ng "shell 没跑"
[ -n "$(j back)" ] && ok "exit 回到列表" || ng "没回到列表"
s=$(j after_sign); echo "$s" | grep -qE "A-1 +在线 +[^ -][^ ]* +(macOS|Debian|Ubuntu|Linux|Alpine)" && ok "列表里有机器名、系统、机型(对方自己报的)" || ng "机器名列: $s"
echo "== 4 移出"
[ -n "$(j removed)" ] && ! echo "$(j after_remove2)" | grep -q "A-1  " && ok "d + y: 移出 A-1" || ng "移出: $(j after_remove2)"
echo "== 5 上锁"
s=$(j after_lock); [ -n "$(j locked)" ] && echo "$s" | grep -q "u 解锁主钥匙" && ! echo "$s" | grep -q "a 批准" && ok "l 上锁: 管理功能藏起来, 提示 u 解锁" || ng "上锁: $s"
ssh-add -L 2>/dev/null | grep -q custhub-master && ng "上锁后 agent 里还有主钥匙" || ok "agent 里没有主钥匙了"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
