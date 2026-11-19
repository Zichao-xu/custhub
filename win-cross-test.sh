#!/usr/bin/env bash
# 跨机器验收: 本机(工程师 e + 中继 r) ─局域网─ Windows 目标机 b
#   ./win-cross-test.sh <Windows 的 ssh 主机> <本机在局域网里的地址>
#   b 只主动往外连本机的中继(Windows 上不开任何入站端口), e 经 r 开 b 的 shell 和端口
#   ssh 只用来把 b 的文件拷过去、在那边起 b 的守护进程、事后检查和清理
set -uo pipefail
cd "$(dirname "$0")"
H=${1:?用法: ./win-cross-test.sh <Windows 的 ssh 主机> <本机局域网地址>}
ME=${2:?用法: ./win-cross-test.sh <Windows 的 ssh 主机> <本机局域网地址>}
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d)
cleanup(){ kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; ssh "$H" 'powershell -NoProfile -Command "Get-Process mesh -ErrorAction SilentlyContinue | Stop-Process -Force; Remove-Item -Recurse -Force $env:TEMP\meshx -ErrorAction SilentlyContinue"' >/dev/null 2>&1; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"; }
trap cleanup EXIT
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
t60(){ perl -e 'alarm shift; exec @ARGV' 60 "$@"; }
V=vendor
zig cc -target x86_64-windows-gnu -std=c99 -O2 -Wall -Wextra -Wno-unused-parameter -DCH_VERSION='"0.0.0"' -DCH_PLAT='"win-x64"' -o "$T/mesh.exe" \
  mesh_main.c main.c util.c b64.c noise.c link.c hop.c disc.c qual.c upnp.c app.c pass.c svc.c rel.c join.c kdf.c sh.c sig.c key.c tui.c plat_win.c plat_win10.c \
  sshsig.c $V/monocypher.c $V/monocypher-ed25519.c -lws2_32 -ladvapi32 -lshell32 -luser32 || exit 1
rm -f "$T"/*.pdb
base=$((20000 + RANDOM % 20000))
ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r e b; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "relay r $(cat "$T/r.pub") $ME:$base"; echo "node e $(cat "$T/e.pub")"; echo "node b $(cat "$T/b.pub")"; echo "--end--"; } >"$T/data"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/data" 2>/dev/null; cat "$T/data" "$T/data.sig" >"$T/trust"
i=0; for n in r e b; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s\nhello host-%s\n' "$(cat "$T/master.pub")" $((base+10+i)) "$( [ $n = b ] && echo b.log || echo "$T/$n.log")" "$n" >"$T/$n/conf"
  cp "$T/trust" "$T/$n/trust"
done
echo "allow 22" >>"$T/b/conf"
echo "relay off" >>"$T/e/conf"; echo "relay off" >>"$T/b/conf"
for n in r e b; do echo "upnp off" >>"$T/$n/conf"; done   # 测试不碰真路由器                              # Windows 自带 OpenSSH Server 的 22, 当普通端口测
. ./testlib.sh
mkpass "$T/master" "$T/e/pass" "$(cat "$T/e.pub")" "$(cat "$T/b.pub")" "sh port:22"
rm -f "$T/master"

echo "== 起节点(r、e 在本机; b 在 $H)"
mkdir -p "$T/wb"; cp -r "$T/b" "$T/mesh.exe" "$T/wb/"
ssh "$H" 'powershell -NoProfile -Command "Remove-Item -Recurse -Force $env:TEMP\meshx -ErrorAction SilentlyContinue"' >/dev/null 2>&1
scp -q -r "$T/wb" "$H":'%TEMP%/meshx' 2>/dev/null || scp -q -r "$T/wb" "$H":'C:/Users/Administrator/AppData/Local/Temp/meshx' || { ng "拷不过去"; exit 1; }
$M run "$T/r" 2>/dev/null & $M run "$T/e" 2>/dev/null &
ssh "$H" 'cmd /c "cd /d %TEMP%\meshx && mesh.exe run b"' >/dev/null 2>&1 &     # ssh 会话一断它就跟着停
b_up(){ $M ls "$T/r" | grep -qE "^  b .*(入站|通)"; }
for _ in $(seq 80); do b_up && break; sleep 0.25; done
b_up && ok "Windows 上的 b 经局域网挂上本机中继 r" || { ng "b 没挂上 r"; $M ls "$T/r"; }
S(){ t60 $M sh "$T/e" b "$@"; }

echo "== 1 跑命令(经中继)"
o=$(S -- echo hello </dev/null | od -An -tx1 | tr -d ' \n'); c=$?
[ "$o" = 68656c6c6f0d0a ] && [ $c = 0 ] && ok "输出原样(cmd 的 CRLF), 退出码 0" || ng "echo: $o $c"
S -- exit 4 </dev/null >/dev/null; c=$?
[ $c = 4 ] && ok "退出码原样带回(4)" || ng "退出码 $c"
o=$(S -- echo 中文测试 </dev/null | od -An -tx1 | tr -d ' \n')
[ "$o" = e4b8ade69687e6b58be8af950d0a ] && ok "中文命令和输出都是 UTF-8" || ng "中文: $o"
o=$(S -- whoami </dev/null | tr -d '\r')
[ -n "$o" ] && ok "以 b 守护进程的身份跑($o)" || ng "whoami 没输出"
o=$(printf 'abc\r\n' | S -- 'findstr x*' | tr -d '\r')
[ "$o" = abc ] && ok "标准输入送到对方, 到头后命令结束" || ng "标准输入: [$o]"
t0=$(perl -MTime::HiRes=time -e 'print time')
n=$(S -- powershell -NoProfile -Command "'x'*3000000" </dev/null | tr -cd x | wc -c | tr -d ' ')
t1=$(perl -MTime::HiRes=time -e 'print time')
[ "$n" = 3000000 ] && ok "3MB 输出一个字节不少($(perl -e "printf '%.1f', 3/($t1-$t0)") MB/s, 含起 PowerShell)" || ng "大输出只收到 $n"

echo "== 2 交互(ConPTY)"
o=$(printf 'echo hi-zz\r\nexit 6\r\n' | S | tr -d '\r'); c=$?
echo "$o" | grep -v echo | grep -q "hi-zz" && [ $c = 6 ] && ok "管道喂给 PowerShell: 输出对, 退出码 6" || ng "交互: $c [$(echo "$o" | head -c 300)]"
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
def until(pat, t=15):
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
until(b"PS ", 15)
say(b"'W='+[Console]::WindowWidth+'x'+[Console]::WindowHeight\r"); print("size1", until(b"W=100x30"))
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0)); os.kill(pid, signal.SIGWINCH); time.sleep(1.0)
say(b"'W='+[Console]::WindowWidth+'x'+[Console]::WindowHeight\r"); print("size2", until(b"W=120x40"))
say(b"ping -t 127.0.0.1\r"); until(b"127.0.0.1", 8); time.sleep(1.5); buf = b""
t0 = time.time(); say(b"\x03")
print("ctrlc", until(b"PS ", 8) and time.time() - t0 < 8)
say(b"'still-'+(40+2)\r"); print("alive", until(b"still-42"))
say(b"exit 5\r")
_, st = os.waitpid(pid, 0)
print("exit", os.WEXITSTATUS(st))
PY
grep -q "size1 True" "$T/tty.out" && ok "真终端: 窗口大小按工程师终端(100x30)" || ng "窗口大小: $(tr '\n' ' ' <"$T/tty.out")"
grep -q "size2 True" "$T/tty.out" && ok "工程师拉大窗口, Windows 那边跟着变(120x40)" || ng "窗口变化没传过去"
grep -q "ctrlc True" "$T/tty.out" && grep -q "alive True" "$T/tty.out" && ok "Ctrl-C 打断对方的 ping -t, 会话还在" || ng "Ctrl-C: $(tr '\n' ' ' <"$T/tty.out")"
grep -q "exit 5" "$T/tty.out" && ok "交互退出码带回(5)" || ng "交互退出码: $(tr '\n' ' ' <"$T/tty.out")"

echo "== 3 端口"
o=$(printf '' | t60 $M connect "$T/e" b 22 2>&1 | head -1 | tr -d '\r')
echo "$o" | grep -q "^SSH-2.0-" && ok "经中继连 b 的 22 口, 收到横幅($o)" || ng "端口 22: [$o]"

echo "== 4 工程师那头走了"
( sleep 60 | $M sh "$T/e" b -- 'ping -n 300 127.0.0.1' >/dev/null 2>&1 ) &
rps(){ ssh "$H" "powershell -NoProfile -EncodedCommand $(printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE | base64)" 2>/dev/null | tr -d '\r'; }   # 远程跑一段 PowerShell(免引号嵌套)
cnt(){ rps '@(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "PING.EXE" -and $_.CommandLine -match "-n 300" }).Count' | tail -1; }
for _ in $(seq 20); do [ "$(cnt)" -ge 1 ] 2>/dev/null && break; sleep 0.5; done
n=$(cnt); [ "$n" -ge 1 ] 2>/dev/null && ok "长命令在 b 上跑" || { ng "长命令没起来: [$n]"; rps 'Get-CimInstance Win32_Process | Where-Object { $_.Name -match "PING|cmd|mesh" } | ForEach-Object { "$($_.ProcessId) $($_.Name) $($_.CommandLine)" }'; }
pkill -f "mesh sh $T/e b"; sleep 4
n=$(cnt); [ "$n" = 0 ] && ok "工程师走了, b 上的进程树收掉了" || ng "b 上还剩 ping: [$n]"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
