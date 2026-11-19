#!/bin/sh
# custhub 接入(Linux / OpenWrt / macOS): curl -fsSL https://github.com/__REPO__/releases/latest/download/custhub3-join.sh | sh
#   认平台 → 取发布清单、本平台程序、种子(GitHub 直连 → ghfast → gh-proxy; curl / wget / uclient-fetch 有哪个用哪个)
#   → 按清单里的 sha512 核对程序 → custhub join --seed(装进安装目录、注册系统服务、报到、显示接入码)
#   环境变量: CUSTHUB_BASE 下载地址(默认 https://github.com/__REPO__/releases), CUSTHUB_JOIN_ARGS 额外给 join 的参数
#   管理电脑(用户模式, 不要 root): curl -fsSL …/custhub3-join.sh | CUSTHUB_JOIN_ARGS=--user sh
set -e
REPO=__REPO__
BASE=${CUSTHUB_BASE:-https://github.com/$REPO/releases}
say(){ printf '%s\n' "$*" >&2; }
die(){ say "✘ $*"; exit 1; }
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64|Linux/amd64)        PLAT=linux-amd64 ;;
  Linux/aarch64|Linux/arm64)       PLAT=linux-arm64 ;;
  Linux/armv5*|Linux/armv6*|Linux/armv7*|Linux/armv8l) PLAT=linux-armv5 ;;
  Linux/mips)                      PLAT=linux-mips ;;
  Linux/mips*)  # 大端 / 小端
    if [ "$(printf I | od -An -tx2 | tr -d ' ')" = 4900 ]; then PLAT=linux-mips; else PLAT=linux-mipsel; fi ;;
  Darwin/arm64)                    PLAT=mac-arm64 ;;
  Darwin/x86_64)                   PLAT=mac-x64 ;;
  *) die "不支持这台机器: $(uname -s) $(uname -m)" ;;
esac
T=$(mktemp -d 2>/dev/null || mktemp -d -t custhub); trap 'rm -rf "$T"' EXIT
fetch(){  # fetch 网址 输出文件: 依次试直连和两个国内能用的镜像
  for p in "" https://ghfast.top/ https://gh-proxy.com/; do
    case $1 in https://github.com/*) ;; *) [ -n "$p" ] && continue ;; esac
    if command -v curl >/dev/null 2>&1; then curl -fsSL --connect-timeout 15 --max-time 300 -o "$2" "$p$1" 2>/dev/null && return 0; fi
    if command -v wget >/dev/null 2>&1; then wget -q -T 30 -O "$2" "$p$1" 2>/dev/null && return 0; fi
    if command -v uclient-fetch >/dev/null 2>&1; then uclient-fetch -q -T 30 -O "$2" "$p$1" 2>/dev/null && return 0; fi
  done
  return 1
}
sha512(){ if command -v sha512sum >/dev/null 2>&1; then sha512sum "$1"; elif command -v shasum >/dev/null 2>&1; then shasum -a 512 "$1"; elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha512 -r "$1"; else return 1; fi | cut -d' ' -f1; }
say "custhub 接入: 平台 $PLAT"
fetch "$BASE/latest/download/custhub3.release" "$T/rel" || die "取不到发布清单(网络不通?)"
V=$(sed -n 's/^version //p' "$T/rel"); L=$(grep "^file $PLAT " "$T/rel" || true)
[ -n "$V" ] && [ -n "$L" ] || die "发布清单里没有 $PLAT 的程序"
EXT=; case $PLAT in win*) EXT=.exe ;; esac
say "  版本 $V, 下载程序…"
fetch "$BASE/download/v$V/custhub3-$V-$PLAT$EXT" "$T/custhub" || die "下载不了程序"
fetch "$BASE/latest/download/custhub3.seed" "$T/seed" || die "下载不了种子"
WANT=$(echo "$L" | cut -d' ' -f4); GOT=$(sha512 "$T/custhub" || true)
if [ -z "$GOT" ]; then say "  (这台机器没有算 sha512 的工具, 跳过核对)"
elif [ "$GOT" != "$WANT" ]; then die "程序的 sha512 和发布清单对不上, 不装"
fi
chmod +x "$T/custhub"
case " ${CUSTHUB_JOIN_ARGS:-} " in *" --user "*) USERMODE=1 ;; *) USERMODE= ;; esac   # 用户模式(管理电脑): 不用 sudo
if [ "$(id -u)" = 0 ] || [ -n "$USERMODE" ]; then "$T/custhub" join --seed "$T/seed" ${CUSTHUB_JOIN_ARGS:-}
elif command -v sudo >/dev/null 2>&1; then say "  要管理员权限(会问一次开机密码)"; sudo "$T/custhub" join --seed "$T/seed" ${CUSTHUB_JOIN_ARGS:-}
else die "要 root 权限"
fi
