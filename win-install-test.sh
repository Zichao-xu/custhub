#!/usr/bin/env bash
# Windows 真装验收: ./win-install-test.sh <Windows 的 ssh 主机> <本机局域网地址>
#   真的 custhub join(装进 C:\ProgramData\custhub、注册计划任务、以 SYSTEM 跑), 测完 custhub remove, 确认没有残留
#   本机: 可达节点 r + 管理员节点 adm(0.3.1) + 假 GitHub; Windows 节点装 0.3.0, 看到 adm 报的 0.3.1 就去取、换上、接班
#   1 join → 批准 → 计划任务在、进程是 SYSTEM
#   2 SYSTEM 身份下的 shell: 跑命令、ConPTY 交互、Ctrl-C
#   3 升级: WinHTTP 从假 GitHub 取包、换上正在跑的程序、新进程接班、转正
#   4 remove: 任务、进程、安装目录都没了
set -uo pipefail
cd "$(dirname "$0")"
H=${1:?用法: ./win-install-test.sh <Windows 的 ssh 主机> <本机局域网地址>}
ME=${2:?用法: ./win-install-test.sh <Windows 的 ssh 主机> <本机局域网地址>}
T=$(mktemp -d)
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*2))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
rps(){ ssh "$H" "powershell -NoProfile -EncodedCommand $(printf '%s' "\$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(\$false); $1" | iconv -f UTF-8 -t UTF-16LE | base64)" 2>/dev/null | tr -d '\r'; }
cleanup(){
  rps 'if (Test-Path "$env:TEMP\chi\custhub.exe") { & "$env:TEMP\chi\custhub.exe" remove | Out-Null }; Get-Process custhub -ErrorAction SilentlyContinue | Stop-Process -Force; schtasks /delete /tn custhub /f 2>$null | Out-Null; Remove-Item -Recurse -Force "$env:ProgramData\custhub","$env:TEMP\chi" -ErrorAction SilentlyContinue' >/dev/null
  kill $(jobs -p) ${SSH_AGENT_PID:-} 2>/dev/null; wait 2>/dev/null
  [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"
}
trap cleanup EXIT
base=${PORT_BASE:-$((20000 + RANDOM % 20000))}; PR=$base GH=$((base+1))
echo "== 构建"
OUT=$T/mesh VER=0.3.1 PLAT=mac ./build.sh >/dev/null || exit 1
M=$T/mesh
for v in 0.3.0 0.3.1; do OUTDIR=$T/w$v VER=$v ONLY=win-x64 ./build.sh release >/dev/null || exit 1; done
W0=$T/w0.3.0/custhub3-0.3.0-win-x64.exe W1=$T/w0.3.1/custhub3-0.3.1-win-x64.exe
eval "$(ssh-agent -s)" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C custhub-master -f "$T/master"; ssh-add -q "$T/master" 2>/dev/null
for n in r adm; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "relay r $(cat "$T/r.pub") $ME:$PR"; echo "node adm $(cat "$T/adm.pub")"; echo "--end--"; } >"$T/d1"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/d1" 2>/dev/null; cat "$T/d1" "$T/d1.sig" >"$T/t1"
i=0; for n in r adm; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s/%s.log\nupnp off\n' "$(cut -d' ' -f1,2 "$T/master.pub")" $((base+10+i)) "$T" "$n" >"$T/$n/conf"; cp "$T/t1" "$T/$n/trust"
done
echo "relay off" >>"$T/adm/conf"
mkdir -p "$T/gh"; (cd "$T/gh" && exec python3 -m http.server "$GH" --bind 0.0.0.0) >/dev/null 2>&1 &
for n in r adm; do CUSTHUB_MESH_PENDING_S=3 $M run "$T/$n" 2>/dev/null & done
K(){ $M key --dir "$T/adm" "$@"; }
sleep 2
K seed --github none/none --out "$T/seed" 2>/dev/null
printf 'upnp off\nrelay off\nrelease_base http://%s:%s/\n' "$ME" "$GH" >"$T/preconf"    # join 会保留这几项

echo "== 1 join(真装)"
rps 'Get-Process custhub -ErrorAction SilentlyContinue | Stop-Process -Force; schtasks /delete /tn custhub /f 2>$null | Out-Null; Remove-Item -Recurse -Force "$env:ProgramData\custhub","$env:TEMP\chi" -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force "$env:TEMP\chi","$env:ProgramData\custhub\node" | Out-Null' >/dev/null
WT=$(rps '$env:TEMP' | tail -1 | tr '\\' '/'); WP=$(rps '$env:ProgramData' | tail -1 | tr '\\' '/')   # scp 不展开 %TEMP%
scp -q "$W0" "$H":"$WT/chi/custhub.exe" && scp -q "$T/seed" "$H":"$WT/chi/seed" && scp -q "$T/preconf" "$H":"$WP/custhub/node/conf" || { ng "拷不过去($WT $WP)"; exit 1; }
ssh "$H" 'cmd /c "%TEMP%\chi\custhub.exe join --seed %TEMP%\chi\seed --wait 90"' >"$T/join.out" 2>&1 &
wait_for 30 grep -q "接入码" "$T/join.out"
code=$(sed -n 's/^  接入码: \([0-9A-Z]\{3\}-[0-9A-Z]\{3\}\).*/\1/p' "$T/join.out" | tr -d '\r')
[ -n "$code" ] && ok "join 显示接入码 $code" || { ng "join 输出: $(cat "$T/join.out")"; exit 1; }
wait_for 30 sh -c "$M key --dir $T/adm pending | grep -q $code"
K approve "$code" win1 >/dev/null 2>&1 && ok "管理员按接入码批准 win1" || ng "批准失败: $(K pending)"
wait_for 60 grep -q "已接入: 名字 win1" "$T/join.out"
grep -q "已接入: 名字 win1" "$T/join.out" && ok "join 显示已接入" || ng "join 输出: $(tail -4 "$T/join.out")"
o=$(rps '(schtasks /query /tn custhub /fo csv /nh) -join ""; $p = Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "custhub.exe" -and $_.CommandLine -match " run " } | Select-Object -First 1; if ($p) { (Invoke-CimMethod -InputObject $p -MethodName GetOwner).User }')
echo "$o" | grep -q '"\\custhub"' && ok "计划任务 custhub 注册了" || ng "计划任务: $o"
echo "$o" | grep -qx "SYSTEM" && ok "custhub run 以 SYSTEM 身份在跑" || ng "进程身份: $o"

o=$(rps '(Get-Acl "$env:ProgramData\custhub").Access | ForEach-Object { $_.IdentityReference.Value }; "inherit=" + (Get-Acl "$env:ProgramData\custhub").AreAccessRulesProtected')
echo "$o" | grep -q "inherit=True" && ! echo "$o" | grep -qiE "Users|Everyone|Authenticated" && echo "$o" | grep -q "SYSTEM" && ok "安装目录只给 SYSTEM 和 Administrators(不继承 ProgramData 的 Users 可读)" || ng "访问控制: $(echo "$o" | tr '\n' ' ')"
echo "== 2 SYSTEM 身份下的 shell"
K pass --to win1 --svc sh 2>/dev/null
o=$(perl -e 'alarm 60; exec @ARGV' $M sh "$T/adm" win1 -- whoami </dev/null | tr -d '\r')
[ "$o" = "nt authority\\system" ] && ok "跑命令: whoami = $o" || ng "whoami: [$o]"
o=$(perl -e 'alarm 60; exec @ARGV' $M sh "$T/adm" win1 -- echo 中文 </dev/null | od -An -tx1 | tr -d ' \n')
[ "$o" = e4b8ade696870d0a ] && ok "SYSTEM 下中文输出也是 UTF-8" || ng "中文: $o"
python3 - "$M" "$T/adm" >"$T/tty.out" 2>&1 <<'PY'
import os, pty, sys, time, struct, fcntl, termios, signal, select
m, d = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid != 0:
    signal.signal(signal.SIGALRM, lambda *a: (print("timeout"), os.kill(pid, signal.SIGKILL))); signal.alarm(120)
if pid == 0:
    os.environ["TERM"] = "xterm-256color"; os.execv(m, [m, "sh", d, "win1"])
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
until(b"PS ", 20)
say(b"'W='+[Console]::WindowWidth\r"); print("size", until(b"W=100"))
say(b"ping -t 127.0.0.1\r"); until(b"127.0.0.1", 8); time.sleep(1.5); buf = b""
t0 = time.time(); say(b"\x03"); print("ctrlc", until(b"PS ", 8) and time.time() - t0 < 8)
say(b"exit 4\r")
_, st = os.waitpid(pid, 0); print("exit", os.WEXITSTATUS(st))
PY
grep -q "size True" "$T/tty.out" && grep -q "ctrlc True" "$T/tty.out" && grep -q "exit 4" "$T/tty.out" && ok "ConPTY 交互: 窗口大小对、Ctrl-C 打断 ping -t、退出码带回" || ng "交互: $(tr '\n' ' ' <"$T/tty.out")"

echo "== 3 升级"
cp "$W1" "$T/gh/custhub3-0.3.1-win-x64.exe"
K release 0.3.1 "$T/gh/custhub3-0.3.1-win-x64.exe" --out "$T/gh/custhub3.release" 2>/dev/null
wait_for 120 sh -c "rps() { :; }; $M ls $T/adm >/dev/null; perl -e 'alarm 20; exec @ARGV' $M sh $T/adm win1 -- '\"%ProgramData%\\custhub\\custhub.exe\" version' </dev/null 2>/dev/null | grep -q 'custhub 0.3.1'"
o=$(perl -e 'alarm 30; exec @ARGV' $M sh "$T/adm" win1 -- '"%ProgramData%\custhub\custhub.exe" version' </dev/null 2>/dev/null | tr -d '\r')
echo "$o" | grep -q "^custhub 0.3.1 win-x64" && ok "Windows 节点取到 0.3.1、换上正在跑的程序、新进程接班: $o" || ng "升级后版本: [$o]"
lg=$(rps 'Get-Content "$env:ProgramData\custhub\node\mesh.log" -Encoding UTF8 | Select-String -Pattern "custhub3-0.3.1|已换上|试用|转正|回滚" | ForEach-Object { $_.Line }')
echo "$lg" | grep -q "取 custhub3-0.3.1-win-x64.exe: http://" && ok "包是 WinHTTP 从发布源取的" || ng "取包日志: $lg"
wait_for 60 sh -c "ssh $H 'powershell -NoProfile -Command \"Select-String -Path \$env:ProgramData\\custhub\\node\\mesh.log -Pattern 0.3.1.转正 -Quiet\"' 2>/dev/null | grep -q True"
lg=$(rps 'Get-Content "$env:ProgramData\custhub\node\mesh.log" -Encoding UTF8 | Select-String -Pattern "转正|回滚" | ForEach-Object { $_.Line }')
echo "$lg" | grep -q "0.3.1 转正" && ! echo "$lg" | grep -q "回滚" && ok "新版转正, 没有回滚" || ng "转正日志: $lg"
n=$(rps '@(Get-Process custhub -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*ProgramData*" }).Count')
[ "$n" = 1 ] && ok "只有一份 custhub 在跑" || ng "在跑的 custhub: $n 份"

rps 'Get-Content "$env:ProgramData\custhub\node\mesh.log" -Encoding UTF8 -Tail 25' >"$T/win-mesh.log"   # 留个底, 失败时看
echo "== 4 remove"
o=$(ssh "$H" 'cmd /c "%TEMP%\chi\custhub.exe remove"' 2>&1 | tr -d '\r'); echo "    $o"
sleep 2
o=$(rps '"task=" + [bool](schtasks /query /tn custhub 2>$null); "proc=" + @(Get-Process custhub -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*ProgramData*" }).Count; "dir=" + (Test-Path "$env:ProgramData\custhub")')
echo "$o" | grep -q "task=False" && echo "$o" | grep -q "proc=0" && echo "$o" | grep -q "dir=False" && ok "计划任务、进程、安装目录都没了" || ng "残留: $(echo "$o" | tr '\n' ' ')"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
