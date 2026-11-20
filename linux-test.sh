#!/usr/bin/env bash
# 在 Debian 容器里用 gcc 编译并跑全部 POSIX 验收(本机要有 docker): ./linux-test.sh [套名 …]
#   不给套名 = 全部; 只挂本目录(放在哪里都能跑)
set -e
ALL="purity pass-test test role-test v6-test lan-test punch-test udp-test net-test decentral-test sh-test upnp-test rel-test join-test admin-test group-test tui-test"
if [ "${1:-}" != inside ]; then
  cd "$(dirname "$0")"
  [ $# -gt 0 ] || set -- $ALL
  exec docker run --rm --cap-add=NET_ADMIN -v "$PWD":/src:ro debian:bookworm-slim bash /src/linux-test.sh inside "$@"
fi
shift
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq gcc libc6-dev python3 openssh-client perl procps curl sudo iproute2 iptables >/dev/null 2>&1
mkdir -p /w && cp -r /src /w/mesh && cd /w/mesh && rm -f mesh
CC=gcc ./build.sh 2>/tmp/build.err; grep -c "warning:" /tmp/build.err | sed "s/^/gcc 警告: /"; grep "warning:" /tmp/build.err | sed "s/^/  /"
rc=0
for t in "$@"; do
  printf '%-11s ' "$t"
  if [ "$t" = purity ]; then ./purity.sh || rc=1; continue; fi
  CC=gcc ./"$t".sh >"/tmp/$t.out" 2>&1 || { rc=1; }
  grep -E "结果" "/tmp/$t.out" || echo "(没跑完)"
  grep -E "✘" "/tmp/$t.out" | head -5
done
exit $rc
