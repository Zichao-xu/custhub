#!/usr/bin/env bash
# sh 服务验收(design-v3 §0 第 2 条): 一台可达节点 r + 工程师机 e + 目标机 b(都在名单里) + 名单外持证的访客 g
#   1 跑命令: 输出、退出码、窗口大小、大输出、标准输入
#   2 交互: 从管道喂命令给登录 shell
#   3 拒绝: 没证 / 证里没有 sh / 访客的证不含 b
#   4 工程师那头走了, 对方的 shell 会被收掉
#   5 真终端: 原始模式、窗口大小跟着变、Ctrl-C 只打断对方的命令
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) ${SSH_AGENT_PID:-} 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
t30(){ perl -e 'alarm shift; exec @ARGV' 30 "$@"; }
base=$((20000 + RANDOM % 20000)); PR=$base

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
eval "$(ssh-agent -s)" >/dev/null; ssh-add -q "$T/master" 2>/dev/null
for n in r e b g; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "relay r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node e $(cat "$T/e.pub")"; echo "node b $(cat "$T/b.pub")"; echo "--end--"; } >"$T/data"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/data" 2>/dev/null; cat "$T/data" "$T/data.sig" >"$T/trust"
i=0; for n in r e b g; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s\nhello host-%s\n' "$(cat "$T/master.pub")" $((base+10+i)) "$T/$n.log" "$n" >"$T/$n/conf"
  [ $n = r ] || echo "relay off" >>"$T/$n/conf"
  echo "upnp off" >>"$T/$n/conf"                        # 测试不碰真路由器
  cp "$T/trust" "$T/$n/trust"
done
$M key --dir "$T/e" pass --to b --svc sh 2>/dev/null || ng "给 e 签发失败"
$M key --dir "$T/e" pass --for "$(cat "$T/g.pub")" --to e --svc sh --out "$T/g/pass" 2>/dev/null || ng "给访客 g 签发失败"
for n in r e b g; do $M run "$T/$n" 2>/dev/null & done
up(){ $M ls "$T/$1" | awk '/^挂着/{f=1;next} /^链路/{f=0} f' | grep -q ' 通$'; }
for _ in $(seq 60); do up e && up b && up g && break; sleep 0.25; done
up e && up b && ok "e、b 挂上可达节点, 访客 g 也挂上" || ng "挂上超时"
S(){ t30 $M sh "$T/e" b "$@"; }

echo "== 1 跑命令"
o=$(S -- echo hello </dev/null | od -An -c | tr -s ' ' | sed 's/ *$//'); c=$?
[ "$o" = " h e l l o \n" ] && [ $c = 0 ] && ok "命令模式输出逐字节原样(没有 \\r、没有回显), 退出码 0" || ng "echo: [$o] $c"
S -- 'exit 3' </dev/null >/dev/null; c=$?
[ $c = 3 ] && ok "退出码原样带回(3)" || ng "退出码: $c"
S -- 'kill -9 $$' </dev/null >/dev/null; c=$?
[ $c = 137 ] && ok "被信号杀: 128+9" || ng "被杀退出码: $c"
o=$(S -- stty size </dev/null | tr -d '\r')
[ "$o" = "24 80" ] && ok "不是终端时窗口按 24x80" || ng "窗口大小: [$o]"
o=$(TERM=screen-256color S -- 'echo $TERM' </dev/null)
[ "$o" = screen-256color ] && ok "工程师的 TERM 带过去($o)" || ng "TERM: [$o]"
o=$(env -u TERM perl -e 'alarm 30; exec @ARGV' $M sh "$T/e" b -- 'echo $TERM' </dev/null)
[ "$o" = xterm-256color ] && ok "工程师没设 TERM 时用 xterm-256color" || ng "默认 TERM: [$o]"
n=$(S -- 'head -c 3000000 /dev/zero | tr "\0" x' </dev/null | tr -cd x | wc -c | tr -d ' ')
[ "$n" = 3000000 ] && ok "3MB 输出一个字节不少" || ng "大输出只收到 $n"
o=$(printf 'abc\n' | S -- 'read x; echo got-$x' | tr -d '\r')
echo "$o" | grep -qx "got-abc" && ok "标准输入送到对方" || ng "标准输入: [$o]"
o=$(S -- 'id -un' </dev/null | tr -d '\r')
[ "$o" = "$(id -un)" ] && ok "以守护进程的身份跑($o)" || ng "身份: [$o]"

echo "== 2 交互"
o=$(printf 'echo hi-$((1+2))\nexit 7\n' | S | tr -d '\r' | sed $'s/\x1b\\[[?0-9;]*[a-zA-Z]//g'); c=$?   # 去掉终端控制码(bash 5.2 的括号粘贴模式)
echo "$o" | grep -q "^hi-3$" && [ $c = 7 ] && ok "管道喂给登录 shell: 输出对, 退出码 7" || ng "交互: $c [$o]"

echo "== 3 拒绝"
cp "$T/e/pass" "$T/e.pass"; rm -f "$T/e/pass"
o=$(S -- true 2>&1 </dev/null); c=$?
echo "$o" | grep -q "没有通行证" && [ $c = 255 ] && ok "没通行证被拒: $o" || ng "没证: $c $o"
$M key --dir "$T/e" pass --to b --svc "port:*" 2>/dev/null
o=$(S -- true 2>&1 </dev/null)
echo "$o" | grep -q "不含这项服务" && ok "通行证没有 sh 被拒: $o" || ng "证里无 sh: $o"
cp "$T/e.pass" "$T/e/pass"
o=$(t30 $M sh "$T/g" b -- true 2>&1 </dev/null)
echo "$o" | grep -q "不含这台机器" && ok "访客开通行证外的 b 被可达节点拦下: $o" || ng "访客开 b: $o"
o=$(t30 $M sh "$T/g" e -- echo from-guest 2>&1 </dev/null | tr -d '\r')
echo "$o" | grep -q "没有通行证\|不含这项服务" && ng "访客开 e 被拒(e 上应该能开): $o" || { [ "$o" = from-guest ] && ok "访客凭证开 e 的 shell" || ng "访客开 e: [$o]"; }

echo "== 4 工程师那头走了"
( sleep 30 | $M sh "$T/e" b -- 'echo started; sleep 300' >"$T/long.out" 2>&1 ) &
LP=$!
for _ in $(seq 40); do grep -q started "$T/long.out" 2>/dev/null && break; sleep 0.25; done
pgrep -f "sleep 300" >/dev/null && ok "长命令在跑" || ng "长命令没起来"
pkill -f "mesh sh $T/e b" ; kill $LP 2>/dev/null
for _ in $(seq 40); do pgrep -f "sleep 300" >/dev/null || break; sleep 0.25; done
pgrep -f "sleep 300" >/dev/null && { ng "工程师走了, 对方的 shell 还在"; pkill -f "sleep 300"; } || ok "工程师走了, 对方的 shell 收掉了"
grep -q "工程师那头走了" "$T/b.log" && ok "b 记下了会话结束" || ng "b 日志里没有会话结束"

echo "== 5 真终端(python pty 模拟工程师的终端)"
python3 - "$M" "$T/e" >"$T/tty.out" 2>&1 <<'PY'
import os, pty, sys, time, struct, fcntl, termios, signal, select
m, d = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid != 0:
    signal.signal(signal.SIGALRM, lambda *a: (print("timeout"), os.kill(pid, signal.SIGKILL)))
    signal.alarm(120)                       # 整段最多 2 分钟, 卡住也不会一直挂着
if pid == 0:
    os.environ["TERM"] = "xterm-256color"
    os.execv(m, [m, "sh", d, "b"])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
buf = b""
def until(pat, t=10):
    global buf
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try: buf += os.read(fd, 65536)
            except OSError: break
        if pat in buf: return True
    return False
def say(x): os.write(fd, x)
time.sleep(0.5)
say(b"PS1='P> '\n"); until(b"P> ")
say(b"stty size\n"); print("size1", until(b"30 100"))
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0)); os.kill(pid, signal.SIGWINCH); time.sleep(0.8)
say(b"stty size\n"); print("size2", until(b"40 120"))
say(b"sleep 30; echo NOT-INTERRUPTED\n"); until(b"no-such-thing", 1.0); buf = b""   # 读空(含远端回显的命令行)
t0 = time.time(); say(b"\x03")
print("ctrlc", until(b"P> ", 5) and b"NOT-INTERRUPTED" not in buf and time.time() - t0 < 5)
say(b"echo still-$((40+2))\n"); print("alive", until(b"still-42"))
say(b"exit 5\n")
_, st = os.waitpid(pid, 0)
print("exit", os.WEXITSTATUS(st))
PY
grep -q "size1 True" "$T/tty.out" && ok "交互: 窗口大小按工程师终端(30x100)" || ng "交互窗口大小: $(cat "$T/tty.out")"
grep -q "size2 True" "$T/tty.out" && ok "工程师拉大窗口, 对方跟着变(40x120)" || ng "窗口变化没传过去"
grep -q "ctrlc True" "$T/tty.out" && grep -q "alive True" "$T/tty.out" && ok "Ctrl-C 只打断对方的命令, 会话还在" || ng "Ctrl-C: $(cat "$T/tty.out")"
grep -q "exit 5" "$T/tty.out" && ok "交互退出码带回(5)" || ng "交互退出码: $(cat "$T/tty.out")"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
