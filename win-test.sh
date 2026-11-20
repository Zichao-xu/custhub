#!/usr/bin/env bash
# Windows 平台模块实机验收: ./win-test.sh <ssh 主机>
#   这台机器上交叉编译 mesh.exe(Win10 1809 起), 准备 r / e / b 三个节点的钥匙、名单、通行证(主钥匙用完即删)
#   拷到对方 %TEMP%\meshtest, 跑 win-test.ps1(跑命令 / 中文 / 标准输入 / 大输出 / ConPTY 交互 / 拒绝 / 进程树收尾), 再删掉
#   对方要有 OpenSSH Server(管理员账户), 能 scp
set -uo pipefail
cd "$(dirname "$0")"
H=${1:?用法: ./win-test.sh <ssh 主机>}
./build.sh >/dev/null || exit 1
M=$PWD/mesh
B=$(mktemp -d); trap 'rm -rf "$B"' EXIT
V=vendor
zig cc -target x86_64-windows-gnu -std=c99 -O2 -Wall -Wextra -Wno-unused-parameter -DCH_VERSION='"0.0.0"' -DCH_PLAT='"win-x64"' -o "$B/mesh.exe" \
  mesh_main.c main.c util.c b64.c noise.c link.c hop.c disc.c qual.c punch.c upnp.c app.c pass.c svc.c rel.c join.c kdf.c sh.c sig.c key.c tui.c plat_win.c plat_win10.c \
  sshsig.c $V/monocypher.c $V/monocypher-ed25519.c -lws2_32 -ladvapi32 -lshell32 -luser32 || exit 1
rm -f "$B"/*.pdb
ssh-keygen -q -t ed25519 -N '' -C master -f "$B/master"
for n in r e b; do mkdir -p "$B/$n"; $M keygen "$B/$n" >"$B/$n.pub"; done
base=$((20000 + RANDOM % 20000))
{ echo "custhub-mesh-trust 1"; echo "relay r $(cat "$B/r.pub") 127.0.0.1:$base"; echo "node e $(cat "$B/e.pub")"; echo "node b $(cat "$B/b.pub")"; echo "--end--"; } >"$B/data"
ssh-keygen -q -Y sign -f "$B/master" -n custhub-mesh-trust "$B/data" 2>/dev/null; cat "$B/data" "$B/data.sig" >"$B/trust"
i=0; for n in r e b; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s.log\nhello host-%s\n' "$(cat "$B/master.pub")" $((base+10+i)) "$n" "$n" >"$B/$n/conf"
  [ $n = r ] || echo "relay off" >>"$B/$n/conf"
  echo "upnp off" >>"$B/$n/conf"                        # 测试不碰真路由器
  cp "$B/trust" "$B/$n/trust"
done
. ./testlib.sh
mkpass "$B/master" "$B/e/pass" "$(cat "$B/e.pub")" "$(cat "$B/b.pub")" sh
mkpass "$B/master" "$B/e.pass.noshell" "$(cat "$B/e.pub")" "$(cat "$B/b.pub")" "port:*"
rm -f "$B/master" "$B/data" "$B/data.sig"
printf '\xef\xbb\xbf' | cat - win-test.ps1 >"$B/t.ps1"     # Windows PowerShell 5.1 要 BOM 才按 UTF-8 读
ssh "$H" 'cmd /c if exist %TEMP%\meshtest rmdir /s /q %TEMP%\meshtest' >/dev/null 2>&1
scp -q -r "$B" "$H":'%TEMP%/meshtest' 2>/dev/null || scp -q -r "$B" "$H":'C:/Users/Administrator/AppData/Local/Temp/meshtest' || { echo "拷不过去"; exit 1; }
ssh "$H" 'powershell -NoProfile -ExecutionPolicy Bypass -File %TEMP%\meshtest\t.ps1' 2>&1 | tee "$B/out" | grep -v '^[0-9][0-9]-[0-9][0-9] '
ssh "$H" 'cmd /c rmdir /s /q %TEMP%\meshtest' >/dev/null 2>&1
grep -q '失败 0' "$B/out"
