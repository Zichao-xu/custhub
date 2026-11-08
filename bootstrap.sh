#!/bin/bash
# bootstrap.sh <版本> '<入池令牌>' — 一键部署的第二段: 按固定版本从 GitHub(不通就换国内镜像)下载中枢代码,
# 每个文件核对 sha256(指纹写死在本文件里, 本文件的指纹又写死在一键命令里, 镜像改不了内容), 然后安装
# 一键命令由 Mac 上的 hub/join-cmd.sh 生成; 本文件由 hub/release.sh 渲染发布, 别手改
set -euo pipefail
REF=${1:?缺版本}; TOKEN=${2:?缺入池令牌}
REPO='Zichao-xu/custhub'
SUMS='e5ec7a8f3402ace3382dc16390e7b0f33eb17586559eb223af6f87e09d945c7b  install.sh
bfefbd44b699950f803b6b6cdf8fd711e1a63a5406532ffef3f02e7286db7692  custhub
ae708e6c87b0f24215451c2968db4370fb4976182e4364ff3f4224d48d55509e  httpd.py
84ba9823fcd77c1c4758af4ebbb7b907b22f9ffeb2d85285297bf7cbe8e59d03  pool.py
9d6b1f9683619af242cb8ffa5b0074eb672cc65cfdae2b2a026a624b1379fd1c  uninstall.sh'
[ "$(id -u)" = 0 ] || { echo "要 root 跑(sudo -i 后再粘贴)" >&2; exit 1; }
command -v curl >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl >/dev/null; }

urls(){ local f=$1
  echo "https://api.github.com/repos/$REPO/contents/$f?ref=$REF"
  echo "https://raw.githubusercontent.com/$REPO/$REF/$f"
  echo "https://cdn.jsdelivr.net/gh/$REPO@$REF/$f"
  echo "https://ghfast.top/https://raw.githubusercontent.com/$REPO/$REF/$f"
  echo "https://gh-proxy.com/https://raw.githubusercontent.com/$REPO/$REF/$f"
}
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
while read -r sum f; do
  [ -n "$f" ] || continue
  ok=
  for u in $(urls "$f"); do
    curl -fsSL -m 30 -H 'Accept: application/vnd.github.raw' -o "$d/$f" "$u" 2>/dev/null || continue
    if [ "$(sha256sum "$d/$f" | cut -c1-64)" = "$sum" ]; then ok=1; break; fi
    echo "  $f: ${u%%/*/*} 内容不符, 换下一个源" >&2
  done
  [ -n "$ok" ] || { echo "下载 $f 失败: GitHub 和镜像都不通或内容不符" >&2; exit 1; }
done <<<"$SUMS"
echo "[custhub] 代码已下载并校验 (版本 ${REF:0:7})"
CUSTHUB_REF="$REF" CUSTHUB_REPO="$REPO" bash "$d/install.sh" "$TOKEN"
