#!/bin/bash
# uninstall.sh [-y] — 从这台机器上卸掉客户接入中枢(root)。先通知池子"我下线了", 再删服务/防火墙/账号/数据。
#   中枢上装好后在 /usr/local/lib/custhub/uninstall.sh; 挂在这台的客户会断, 卸之前先在 Mac 上把它们重新接到别的中枢
#   -y  不问, 直接卸(有客户也卸)
set -u
[ "$(id -u)" = 0 ] || { echo "要 root 跑" >&2; exit 1; }
S=/var/lib/custhub; W=/srv/custhub; R=/var/lib/custhub-report; P=/var/lib/custhub-pool; L=/usr/local/lib/custhub; IF=cust0

n=0; [ -d "$S/peers" ] && n=$(ls "$S/peers" 2>/dev/null | wc -l)
if [ "$n" -gt 0 ]; then
  echo "这台中枢上还挂着 $n 台客户(卸载后会断):"
  /usr/local/sbin/custhub list 2>/dev/null | while IFS=$'\t' read -r k _ nm h _; do
    printf '  %s.%s  %s  最近握手 %s\n' "$(. "$S/settings"; echo "$NET")" "$k" "$(echo "$nm" | base64 -d 2>/dev/null)" "$( [ "${h:-0}" -gt 0 ] && date -d "@$h" '+%F %T' || echo 从未)"
  done
  if [ "${1:-}" != -y ]; then
    read -r -p "确定卸载? 输入 yes: " a </dev/tty; [ "$a" = yes ] || { echo "已取消"; exit 1; }
  fi
fi

echo "… 通知中枢池: 本机下线"
[ -f "$L/pool.py" ] && runuser -u custhub-www -- env POOL_DIR="$P" python3 -I "$L/pool.py" leave 2>/dev/null | tail -1
systemctl disable --now custhub-pool.timer custhub-http "wg-quick@$IF" custhub-fw 2>/dev/null
for u in /etc/systemd/system/custhub-node-*.socket; do [ -f "$u" ] && systemctl disable --now "${u##*/}" "$(basename "$u" .socket).service" 2>/dev/null; done
rm -f /etc/systemd/system/custhub-node-*.socket /etc/systemd/system/custhub-node-*.service
[ -x "$L/fw-passthru.sh" ] && "$L/fw-passthru.sh" stop
nft delete table inet custhub 2>/dev/null
ip link del "$IF" 2>/dev/null
rm -f /etc/systemd/system/custhub-fw.service /etc/systemd/system/custhub-http.service \
      /etc/systemd/system/custhub-pool.service /etc/systemd/system/custhub-pool.timer \
      "/etc/wireguard/$IF.conf" /usr/local/sbin/custhub /usr/local/sbin/custhub-ssh /usr/local/sbin/custrep-ssh /etc/sudoers.d/custhub
rm -rf "/etc/systemd/system/wg-quick@$IF.service.d" "$S" "$W" "$R" "$P" "$L"
# 管理端(Mac)的复用连接还挂着这个账号的进程时 userdel 会拒绝, 先结束它们
for u in custhub custhub-www custtun custrep; do pkill -u "$u" 2>/dev/null; done; sleep 1
id custtun >/dev/null 2>&1 && userdel -r custtun 2>/dev/null
id custrep >/dev/null 2>&1 && userdel -r custrep 2>/dev/null
id custhub >/dev/null 2>&1 && userdel -r custhub 2>/dev/null
id custhub-www >/dev/null 2>&1 && userdel custhub-www 2>/dev/null
systemctl daemon-reload
echo "✔ 中枢已卸载(依赖包 wireguard-tools/nftables 保留; 云安全组规则请自行删除)"
