#!/usr/bin/env bash
# 在 Debian 容器里用 gcc 编译并跑全部 POSIX 验收(本机要有 docker): ./linux-test.sh [套名 …]
#   不给套名 = 全部; 只挂本目录(放在哪里都能跑); 各套并行跑(JOBS=并行数), 改全局网络设置的单独跑
set -e
ALL="purity pass-test test role-test v6-test lan-test punch-test udp-test net-test decentral-test file-test exec-test alerts-test sh-test upnp-test rel-test join-test admin-test group-test tui-test"
if [ "${1:-}" != inside ]; then
  cd "$(dirname "$0")"
  [ $# -gt 0 ] || set -- $ALL
  exec docker run --rm --cap-add=NET_ADMIN --sysctl net.ipv4.ip_local_port_range="50000 65000" -v "$PWD":/src:ro debian:bookworm-slim bash /src/linux-test.sh inside "$@"
fi
shift
export DEBIAN_FRONTEND=noninteractive
for k in 1 2 3; do                                     # 装依赖: 网络偶尔抽风, 重试; 都不行就说清楚再退出
  apt-get update -qq >/tmp/apt.log 2>&1 && apt-get install -y -qq gcc libc6-dev python3 openssh-client perl procps curl sudo iproute2 iptables >>/tmp/apt.log 2>&1 && break
  [ $k = 3 ] && { echo "容器里装依赖失败(网络?):"; tail -5 /tmp/apt.log; exit 1; }; sleep 5
done
mkdir -p /w && cp -r /src /w/mesh && cd /w/mesh && rm -f mesh
CC=gcc ./build.sh 2>/tmp/build.err || { echo "编译失败:"; grep -A3 "error" /tmp/build.err | head -20; exit 1; }; grep -c "warning:" /tmp/build.err | sed "s/^/gcc 警告: /"; grep "warning:" /tmp/build.err | sed "s/^/  /"
# 并行跑(每套用随机端口、各自的临时目录, 互不干扰); 改全局设置的几套单独跑: net-test(回环加延迟) punch-test(防火墙丢 RST) group-test(装到 /opt、建用户组)
# 系统自动分配的临时端口挪到 50000 以上(上面 docker --sysctl), 各套监听用的 20000~41000 不会被别的连接先占掉
SERIAL=" net-test punch-test group-test "
J=${JOBS:-$(( $(nproc) + 2 ))}
run1(){ CC=gcc CUSTHUB_PREBUILT=1 PORT_BASE=$2 ./"$1".sh >"/tmp/$1.out" 2>&1; echo $? >"/tmp/$1.rc"; }   # 每套一段互不重叠的端口(PORT_BASE 起 1000 个)
i=0
for t in "$@"; do
  i=$((i + 1))
  [ "$t" = purity ] && continue
  case "$SERIAL" in *" $t "*) continue ;; esac
  while [ "$(jobs -rp | wc -l)" -ge "$J" ]; do sleep 0.2; done
  run1 "$t" $((20000 + i * 1000)) &
done
wait
i=0; for t in "$@"; do i=$((i + 1)); case "$SERIAL" in *" $t "*) run1 "$t" $((20000 + i * 1000)) ;; esac; done
rc=0
for t in "$@"; do                                      # 按原来的顺序报
  printf '%-11s ' "$t"
  if [ "$t" = purity ]; then ./purity.sh || rc=1; continue; fi
  grep -E "结果" "/tmp/$t.out" || { echo "(没跑完)"; rc=1; }
  grep -qE "失败 [1-9]" "/tmp/$t.out" && rc=1
  [ "$(cat "/tmp/$t.rc" 2>/dev/null)" = 0 ] || rc=1
  grep -E "✘" "/tmp/$t.out" | head -5
done
exit $rc
