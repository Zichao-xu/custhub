#!/usr/bin/env bash
# 引导脚本验收(一行命令): ./dist-test.sh [Windows 的 ssh 主机 本机局域网地址]
#   sh 版: Debian 容器里起假的 Release 下载站, 认平台 → 下载 → sha512 核对 → join(演练模式)显示接入码; 程序被改过就不装
#   给了 Windows 主机就再测 PowerShell 版(下载站在本机, CUSTHUB_HOME + 演练模式, 不碰系统)
set -uo pipefail
cd "$(dirname "$0")"
WH=${1:-} ME=${2:-}
mk_site(){  # mk_site 目录 平台 程序 主钥匙: 假的 releases/ 目录结构
  local S=$1 P=$2 B=$3 MK=$4 E=; case $P in win*) E=.exe ;; esac
  mkdir -p "$S/latest/download" "$S/download/v0.3.0"
  cp "$B" "$S/download/v0.3.0/custhub3-0.3.0-$P$E"
  { echo "custhub-rel v1"; echo "version 0.3.0"; echo "signed $(date +%s)"
    echo "file $P $(wc -c <"$B" | tr -d ' ') $(shasum -a 512 "$B" 2>/dev/null | cut -d' ' -f1 || sha512sum "$B" | cut -d' ' -f1)"; echo "--end--"; } >"$S/rel"
  rm -f "$S/rel.sig"; ssh-keygen -q -Y sign -f "$MK" -n custhub-rel "$S/rel" 2>/dev/null; cat "$S/rel" "$S/rel.sig" >"$S/latest/download/custhub3.release"
  { echo "custhub-mesh-trust 1"; echo "--end--"; } >"$S/t"; rm -f "$S/t.sig"; ssh-keygen -q -Y sign -f "$MK" -n custhub-mesh-trust "$S/t" 2>/dev/null
  { echo "custhub-seed v1"; echo "master $(cut -d' ' -f1,2 "$MK.pub") custhub-master"; echo "github none/none"; echo "--trust--"; cat "$S/t" "$S/t.sig"; } >"$S/latest/download/custhub3.seed"
  for f in custhub3-join.sh custhub3-join.ps1; do sed "s#__REPO__#none/none#g" "dist/$f" >"$S/latest/download/$f"; done
}
rc=0
echo "== sh 版(Debian 容器)"
docker run --rm -i -v "$PWD":/src:ro debian:bookworm-slim bash -s <<'IN' || rc=1
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq gcc libc6-dev python3 openssh-client curl >/dev/null 2>&1
mkdir -p /w && cp -r /src /w/mesh; cd /w/mesh; T=$(mktemp -d)
P=$(uname -m | sed "s/^x86_64$/linux-amd64/; s/^aarch64$/linux-arm64/")   # 容器的实际架构
CC=gcc OUT=$T/custhub VER=0.3.0 PLAT=$P ./build.sh >/dev/null
ssh-keygen -q -t ed25519 -N '' -C master -f "$T/mk"
eval "$(sed -n '/^mk_site(){/,/^}/p' dist-test.sh)"
shasum(){ sha512sum "$2"; }
mk_site "$T/site" $P "$T/custhub" "$T/mk"
(cd "$T" && exec python3 -m http.server 18080 --bind 127.0.0.1) >/dev/null 2>&1 & sleep 1
pass=0; fail=0; ok(){ echo "  ✔ $*"; pass=$((pass+1)); }; ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
export CUSTHUB_BASE=http://127.0.0.1:18080/site CUSTHUB_HOME=$T/home CUSTHUB_SVC_DRY=1 CUSTHUB_SVC_KIND=systemd CUSTHUB_JOIN_ARGS="--wait 3"
o=$(curl -fsSL $CUSTHUB_BASE/latest/download/custhub3-join.sh | sh 2>&1)
echo "$o" | grep -q "平台 $P" && echo "$o" | grep -q "接入码: [0-9A-Z]\{3\}-[0-9A-Z]\{3\}" && ok "curl … | sh: 认出 $P、下载、核对、join 显示接入码" || ng "输出: $o"
cmp -s "$T/custhub" "$T/home/custhub" && grep -q "^github none/none$" "$T/home/node/conf" && ok "程序装进安装目录, conf 里是种子带的仓库" || ng "安装结果不对"
[ -f "$T/home/node/dry/pid" ] && kill $(cat "$T/home/node/dry/pid") 2>/dev/null; rm -rf "$T/home"
printf 'x' >>"$T/site/download/v0.3.0/custhub3-0.3.0-$P"
o=$(curl -fsSL $CUSTHUB_BASE/latest/download/custhub3-join.sh | sh 2>&1); c=$?
echo "$o" | grep -q "sha512 和发布清单对不上, 不装" && [ $c != 0 ] && [ ! -e "$T/home/custhub" ] && ok "程序被改过: 不装" || ng "改过的程序: $c $o"
echo "  结果: 通过 $pass, 失败 $fail"; [ $fail = 0 ]
IN
if [ -n "$WH" ]; then
  echo "== PowerShell 版($WH)"
  T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
  OUTDIR=$T/b VER=0.3.0 ONLY=win-x64 ./build.sh release >/dev/null || exit 1
  ssh-keygen -q -t ed25519 -N '' -C master -f "$T/mk"
  mk_site "$T/site" win-x64 "$T/b/custhub3-0.3.0-win-x64.exe" "$T/mk"
  PT=$((20000 + RANDOM % 20000))
  (cd "$T" && exec python3 -m http.server "$PT" --bind 0.0.0.0) >/dev/null 2>&1 & sleep 1
  PS='$env:CUSTHUB_BASE="http://'$ME:$PT'/site"; $env:CUSTHUB_HOME="$env:TEMP\chj"; $env:CUSTHUB_SVC_DRY="1"; $env:CUSTHUB_JOIN_ARGS="--wait 3"; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); irm "$env:CUSTHUB_BASE/latest/download/custhub3-join.ps1" | iex; $p = Get-Content "$env:TEMP\chj\node\dry\pid" -ErrorAction SilentlyContinue; if ($p) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue }; Start-Sleep 1; "装了: " + (Test-Path "$env:TEMP\chj\custhub.exe"); Remove-Item -Recurse -Force "$env:TEMP\chj" -ErrorAction SilentlyContinue'
  o=$(ssh "$WH" "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $(printf '%s' "$PS" | iconv -f UTF-8 -t UTF-16LE | base64)" 2>&1 | tr -d '\r')
  if echo "$o" | grep -q "平台 win-x64" && echo "$o" | grep -q "接入码: [0-9A-Z]\{3\}-[0-9A-Z]\{3\}" && echo "$o" | grep -q "装了: True"; then echo "  ✔ irm … | iex: 认出 win-x64、下载、SHA512 核对、join 显示接入码"; else echo "  ✘ 输出: $o"; rc=1; fi
fi
exit $rc
