#!/usr/bin/env bash
# 构建 custhub(v3, 0.3 线)
#   ./build.sh            本机编一份 ./mesh(开发 / 测试用); 环境变量: OUT 输出路径, VER 版本号(默认 0.0.0), PLAT 平台名(默认 dev), CC 编译器
#   ./build.sh release    交叉编译全部发布目标 → ${OUTDIR:-dist/out}/custhub3-<版本>-<平台>[.exe], 版本号取 VERSION(VER 可覆盖), ONLY=平台名前缀 只编一部分
#     一处交叉编译: zig cc(POSIX 目标静态链接 musl; Windows 用 zig 自带 mingw, 链 Win10 自带的 UCRT, 线是 Win10 1809)
# 核心只用 C99 + 平台模块(design-v3 §0): POSIX 目标链 plat_posix.c, Windows 链 plat_win.c; 密码学只用 vendor/ 里的 Monocypher 4.0.2
set -euo pipefail
cd "$(dirname "$0")"
[ -n "${CUSTHUB_PREBUILT:-}" ] && [ "${1:-}" != release ] && [ -z "${OUT:-}${VER:-}${PLAT:-}" ] && [ -x mesh ] && exit 0   # 并行测试: 容器里已经编好一份, 各套别再编(同时写同一个文件会坏)
CORE=(main.c util.c b64.c noise.c link.c hop.c disc.c qual.c punch.c udp.c bench.c file.c exec.c info.c events.c upnp.c app.c pass.c svc.c rel.c join.c kdf.c sh.c sig.c key.c sshsig.c tui.c
      vendor/monocypher.c vendor/monocypher-ed25519.c vendor/ikcp.c)
CF=(-std=c99 -Wall -Wextra -Wno-unused-parameter)

if [ "${1:-}" != release ]; then
  W=; ${CC:-cc} --version 2>/dev/null | grep -qi "gcc\|free software" && W=-Wno-format-truncation   # gcc: snprintf 截断是故意的(装不下就截), 不报
  ${CC:-cc} "${CF[@]}" -O2 $W -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L \
    -DCH_VERSION="\"${VER:-0.0.0}\"" -DCH_PLAT="\"${PLAT:-dev}\"" -o "${OUT:-mesh}" mesh_main.c "${CORE[@]}" plat_posix.c
  echo "${OUT:-mesh} ($(wc -c <"${OUT:-mesh}" | tr -d ' ') 字节)"
  exit 0
fi

V=${VER:-$(tr -d ' \n' <VERSION)}
[[ $V =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || { echo "版本号不对: $V" >&2; exit 1; }
OUT=${OUTDIR:-dist/out}; mkdir -p "$OUT"
RF=("${CF[@]}" -Os -ffunction-sections -fdata-sections -DNDEBUG -DCH_VERSION="\"$V\"")
b(){  # b zig目标 平台名 [额外参数…]
  local t=$1 n=$2; shift 2
  case $n in ${ONLY:-}*) ;; *) return 0 ;; esac
  local ext= plat=(plat_posix.c) libs=(); case $n in win*) ext=.exe; plat=(plat_win.c plat_win10.c); libs=(-lws2_32 -ladvapi32 -lshell32 -luser32 -liphlpapi) ;; esac
  local f="$OUT/custhub3-$V-$n$ext"
  zig cc -target "$t" "${RF[@]}" -DCH_PLAT="\"$n\"" "$@" -o "$f" mesh_main.c "${CORE[@]}" "${plat[@]}" ${libs[@]+"${libs[@]}"}
  rm -f "$f".pdb "${f%.exe}.pdb"
  if [ -n "$ext" ]; then   # 只许依赖 Win10 自带的 DLL(查 PE 导入表; WinHTTP 是运行时按需加载的, 不在表里)
    local bad; bad=$(objdump -p "$f" | awk '/DLL Name:/{print $3}' | grep -viE '^(kernel32|ws2_32|advapi32|shell32|user32|iphlpapi|ucrtbase|api-ms-win-crt-[a-z0-9-]+)\.dll$' || true)
    [ -z "$bad" ] || { echo "$n 依赖了 Win10 不一定自带的 DLL: $bad" >&2; exit 1; }
  fi
  printf '%-14s %8s  %s\n' "$n" "$(wc -c <"$f" | tr -d ' ')" "$(shasum -a 256 "$f" | cut -d' ' -f1)"
}
# Win7 / 8 / 8.1(补丁模块 plat_win7.c): mingw-w64 链 msvcrt(Win7 自带; zig 的 mingw 只有 UCRT, Win7 要装补丁才有), 在容器里编
b7(){  # b7 编译器前缀 平台名
  local cc=$1 n=$2
  case $n in ${ONLY:-}*) ;; *) return 0 ;; esac
  local f="$OUT/custhub3-$V-$n.exe"
  docker image inspect custhub-mingw >/dev/null 2>&1 || printf 'FROM debian:bookworm-slim\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 binutils-mingw-w64 >/dev/null && rm -rf /var/lib/apt/lists/*\n' | docker build -q -t custhub-mingw - >/dev/null
  docker run --rm -v "$PWD":/src:ro -v "$(cd "$OUT" && pwd)":/out -w /src custhub-mingw \
    "$cc-gcc" "${CF[@]}" -Os -fno-strict-aliasing -ffunction-sections -DNDEBUG -D__USE_MINGW_ANSI_STDIO=1 -D_WIN32_WINNT=0x0A00 \
    -DCH_VERSION="\"$V\"" -DCH_PLAT="\"$n\"" -Wl,--gc-sections -s -static -o "/out/${f##*/}" mesh_main.c "${CORE[@]}" plat_win.c plat_win7.c -lws2_32 -ladvapi32 -lshell32 -luser32 -liphlpapi
  local bad; bad=$(objdump -p "$f" | awk '/DLL Name:/{print $3}' | grep -viE '^(kernel32|ws2_32|advapi32|shell32|user32|iphlpapi|msvcrt)\.dll$' || true)
  [ -z "$bad" ] || { echo "$n 依赖了 Win7 不一定自带的 DLL: $bad" >&2; exit 1; }
  printf '%-14s %8s  %s\n' "$n" "$(wc -c <"$f" | tr -d ' ')" "$(shasum -a 256 "$f" | cut -d' ' -f1)"
}
P=(-D_DEFAULT_SOURCE -Wl,--gc-sections -s -static)
b7 x86_64-w64-mingw32    win7-x64
b7 i686-w64-mingw32      win7-x86
b x86_64-windows-gnu      win-x64
b x86-windows-gnu         win-x86
b aarch64-macos           mac-arm64    -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE
b x86_64-macos            mac-x64      -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE
b x86_64-linux-musl       linux-amd64  "${P[@]}"
b aarch64-linux-musl      linux-arm64  "${P[@]}"
b arm-linux-musleabi      linux-armv5  "${P[@]}" -mcpu=arm926ej_s
b mips-linux-musleabi     linux-mips   "${P[@]}" -mcpu=mips32 -msoft-float
b mipsel-linux-musleabi   linux-mipsel "${P[@]}" -mcpu=mips32 -msoft-float
