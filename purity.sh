#!/usr/bin/env bash
# 核心纯粹性检查(design-v3 §0 第 3 条): 核心文件里不许有 #if, 只许 include C99 标准头文件和自己的头文件
#   平台模块 plat_*.c 不查(系统差异本来就该在那里)
set -uo pipefail
cd "$(dirname "$0")"
std='assert|ctype|errno|limits|stdarg|stddef|stdint|stdio|stdlib|string|time'
bad=0
for f in *.c *.h; do
  case $f in plat_*.c) continue ;; esac
  if grep -nE '^\s*#\s*(if|ifdef|ifndef|elif)' "$f" | grep -vE '#ifndef (MESH|PLAT)_H$|#ifndef [A-Z_]+_H$' ; then echo "  ✘ $f 里有条件编译"; bad=1; fi
  if grep -nE '^\s*#\s*include\s*<' "$f" | grep -vE "<($std)\.h>"; then echo "  ✘ $f include 了系统头文件"; bad=1; fi
done
[ $bad = 0 ] && echo "  ✔ 核心纯粹: 没有条件编译, 只用 C99 标准头文件" || exit 1
