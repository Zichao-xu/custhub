#!/usr/bin/env bash
# 发版(0.3 线): dist/release.sh <owner/仓库> [--node 管理员节点目录] [--seed 种子文件] [--only "名字 …"] [--dry]
#   1 编全部发布目标(build.sh release, 版本号取 VERSION)
#   2 用 ssh-agent 里的主钥匙(先 custhub key unlock)签发布清单 custhub3.release、出种子 custhub3.seed(当前名单; 第一次建网用 --seed 给现成的)
#   3 引导脚本 custhub3-join.sh / .ps1 填上仓库名
#   4 gh release create v<版本>(--dry 只做 1~3, 产物在 dist/out)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=${1:?用法: dist/release.sh <owner/仓库> [--node 节点目录] [--only "名字 …"] [--dry]}; shift
NODE=; ONLY=; DRY=0; SEED=; MA=()
while [ $# -gt 0 ]; do case $1 in
  --node) NODE=$2; shift 2 ;; --only) ONLY=$2; shift 2 ;; --dry) DRY=1; shift ;; --seed) SEED=$2; shift 2 ;;
  *) echo "不认识的参数 $1" >&2; exit 2 ;; esac; done
[[ $REPO =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "仓库名不对: $REPO" >&2; exit 2; }
V=$(tr -d ' \n' <VERSION)
O=dist/out; rm -rf "$O"; mkdir -p "$O"
echo "== 编 $V"
OUTDIR=$O ./build.sh release
./build.sh >/dev/null                                    # 本机这份用来签名
K=(./mesh key); [ -n "$NODE" ] && K+=(--dir "$NODE")
ssh-add -L 2>/dev/null | grep -q " custhub-master$" || { echo "主钥匙没解锁: 先 ./mesh key unlock(或 custhub key unlock)" >&2; exit 1; }
[ -n "$SEED" ] && { head -1 "$SEED" | grep -q "^custhub-seed v1$" || { echo "$SEED 不是种子" >&2; exit 1; }; M=$(sed -n "s/^master //p" "$SEED" | cut -d" " -f1,2); MA=(--master "$M"); }
echo "== 签发布清单、出种子"
"${K[@]}" release "$V" "$O"/custhub3-"$V"-* ${ONLY:+--only "$ONLY"} --out "$O/custhub3.release" ${MA[@]+"${MA[@]}"}
if [ -n "$SEED" ]; then cp "$SEED" "$O/custhub3.seed"; else "${K[@]}" seed --github "$REPO" --out "$O/custhub3.seed"; fi
for f in custhub3-join.sh custhub3-join.ps1; do sed "s#__REPO__#$REPO#g" "dist/$f" >"$O/$f"; done
ls -l "$O"
[ $DRY = 1 ] && { echo "(--dry: 没发布)"; exit 0; }
gh release view "v$V" --repo "$REPO" >/dev/null 2>&1 && { echo "Release v$V 已存在: 先改 VERSION" >&2; exit 1; }
gh release create "v$V" --repo "$REPO" --title "custhub v$V" --latest --notes "custhub v$V" "$O"/*
echo "已发布 v$V($REPO)。接入:"
echo "  Linux / OpenWrt / macOS:  curl -fsSL https://github.com/$REPO/releases/latest/download/custhub3-join.sh | sh"
echo "  Windows(管理员 PowerShell): irm https://github.com/$REPO/releases/latest/download/custhub3-join.ps1 | iex"
