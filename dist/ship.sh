#!/usr/bin/env bash
# 一条龙发版: dist/ship.sh "<公开仓库的提交说明>"
#   1 本目录提交干净(发出去的就是提交里的东西)
#   2 全套验收(linux-test.sh)必须全过, 有一项不过就停, 不发
#   3 同步到公开仓库的本地副本(PUB, 默认 ~/.custhub-pub, 没有就克隆)提交推送
#   4 dist/release.sh 发 GitHub Release(主钥匙要先解锁在 ssh-agent 里, colima 要开着)
set -euo pipefail
cd "$(dirname "$0")/.."
MSG=${1:?用法: dist/ship.sh "<公开仓库的提交说明>"}
REPO=${REPO:-Zichao-xu/custhub}
PUB=${PUB:-$HOME/.custhub-pub}
LOG=${TMPDIR:-/tmp}/custhub-ship; mkdir -p "$LOG"
V=$(tr -d ' \n' <VERSION)
[ -z "$(git status --porcelain -- .)" ] || { echo "有没提交的改动, 先提交" >&2; git status --short -- . >&2; exit 1; }
ssh-add -L 2>/dev/null | grep -q " custhub-master$" || { echo "主钥匙没解锁: 先 custhub key unlock" >&2; exit 1; }
gh release view "v$V" -R "$REPO" >/dev/null 2>&1 && { echo "v$V 已经发过, 先改 VERSION" >&2; exit 1; }
echo "== 验收 $V(日志 $LOG/suite.log)"
s=$(date +%s)
if ! ./linux-test.sh >"$LOG/suite.log" 2>&1 || grep -qE "失败 [1-9]|没跑完" "$LOG/suite.log"; then
  echo "验收没全过, 不发:" >&2; grep -E "失败 [1-9]|没跑完|✘" "$LOG/suite.log" >&2; exit 1; fi
echo "   全过($(( $(date +%s) - s )) 秒)"
echo "== 公开仓库 $PUB"
[ -d "$PUB/.git" ] || git clone -q "https://github.com/$REPO.git" "$PUB"
git -C "$PUB" pull -q --ff-only
git ls-files -z . | rsync -a --from0 --files-from=- ./ "$PUB/"
# 本地删掉的文件公开仓库也删
( cd "$PUB" && git ls-files -z | while IFS= read -r -d '' f; do [ -e "$OLDPWD/$f" ] || git rm -q -- "$f"; done )
git -C "$PUB" add -A
if git -C "$PUB" diff --cached --quiet; then echo "   没变化"; else
  git -C "$PUB" -c user.name=Zichao-xu -c user.email=86253726+Zichao-xu@users.noreply.github.com commit -q -m "$V: $MSG"
  git -C "$PUB" push -q; echo "   已推"; fi
echo "== 发版"
dist/release.sh "$REPO" >"$LOG/release.log" 2>&1 || { echo "发版失败:" >&2; tail -8 "$LOG/release.log" >&2; exit 1; }
grep -m1 "releases/tag" "$LOG/release.log"
