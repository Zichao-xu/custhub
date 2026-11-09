#!/bin/bash
# install.sh '<入池令牌 CH1:...>' — 在任意 Debian/Ubuntu 公网机上装/升级客户接入中枢(root, 幂等, 重跑不丢客户)
# 一般不直接跑, 由 bootstrap.sh 下载校验后调用; 令牌由 Mac 上 hub/join-cmd.sh 生成(含池密钥 + Mac 管理公钥 + 已知中枢)
# 可选环境变量(只在首次安装生效): HUB_NAME  HUB_HOST(公网地址, 默认自动探测)  HTTP_PORT(8443)
#
# 中枢做四件事:
#   1. 反向通道: 客户机用受限账号 custtun 挂回拨口 127.0.0.1:22000+N(只能挂自己的口, 出站封死)
#   2. HTTP: 下发接入脚本/安装包 + 收进度回报 + 中枢池报到(httpd.py / pool.py)
#   3. ssh 受限账号 custhub: Mac 只能 (a) 调 custhub 管理命令 (b) 端口转发到本机回拨口(跳板)
#   4. 入池: 向已知中枢报到并定时互换名单, Mac 从任意一台活着的中枢拿到全名单(新中枢热加入, 不用改 Mac 配置)
# (旧版还有 WireGuard cust0 加速通道, 2026-11-09 停用; 升级时自动拆掉)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "要 root 跑" >&2; exit 1; }
SRC=$(cd "$(dirname "$0")" && pwd)
TOKEN=${1:?缺入池令牌(在 Mac 上跑 hub/join-cmd.sh 生成整条命令)}
S=/var/lib/custhub; W=/srv/custhub; R=/var/lib/custhub-report; P=/var/lib/custhub-pool
L=/usr/local/lib/custhub; U=custhub; UW=custhub-www; UT=custtun; UR=custrep
say(){ echo "[custhub] $*"; }

# ---- 解令牌 ----
case $TOKEN in CH1:*) ;; *) echo "令牌格式不对(应以 CH1: 开头)" >&2; exit 1 ;; esac
command -v python3 >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null; }
eval "$(python3 -Ic '
import sys,json,base64,re,shlex
t=json.loads(base64.b64decode(sys.argv[1][4:]))
k,a,s=t["k"],t["a"],t.get("s",[])
assert re.fullmatch(r"[0-9a-f]{64}",k) and re.fullmatch(r"ssh-(ed25519|rsa) [A-Za-z0-9+/=]+( \S+)?",a)
s=[x for x in s if re.fullmatch(r"[A-Za-z0-9.:-]+:[0-9]+",x)]
print("POOL_KEY=%s ADMIN_KEY=%s SEEDS=%s" % (k,shlex.quote(a),shlex.quote(" ".join(s))))
' "$TOKEN" 2>/dev/null)" || { echo "令牌内容无效" >&2; exit 1; }

# ---- 依赖(装过就跳过; apt 源用机器自己的配置) ----
miss=; for c in nft flock curl; do command -v $c >/dev/null || miss=1; done
if [ -n "$miss" ]; then
  say "安装 nftables curl"
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables util-linux curl >/dev/null
fi

# ---- 账号 ----
id "$U" >/dev/null 2>&1 || useradd --system --create-home --home-dir "/home/$U" --shell /bin/sh "$U"
id "$UW" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$UW"
# 客户机挂反向隧道用; shell 必须是 /bin/sh(授权里的强制命令要靠它执行), 但授权行禁了终端, 登不进来
id "$UT" >/dev/null 2>&1 || useradd --system --create-home --home-dir "/home/$UT" --shell /bin/sh "$UT"
install -d -m700 -o "$UT" -g "$UT" "/home/$UT/.ssh"
# 进度回报备用通道(客户机 HTTP 回报被代理弄丢时走 ssh 22): 每次接入一把一次性钥匙, 强制命令只能写那一次的回报
id "$UR" >/dev/null 2>&1 || useradd --system --create-home --home-dir "/home/$UR" --shell /bin/sh "$UR"
install -d -m700 -o "$UR" -g "$UR" "/home/$UR/.ssh"
cat >/usr/local/sbin/custrep-ssh <<'EOF'
#!/bin/sh
# custrep 的强制命令: $1 = 本次接入的码(写死在授权行里), 客户机只能选 log / fail
set -f
case "$SSH_ORIGINAL_COMMAND" in log|fail) ;; *) echo "ERR bad mode" >&2; exit 1 ;; esac
exec sudo -n /usr/local/sbin/custhub rep-in "$1" "$SSH_ORIGINAL_COMMAND"
EOF
chmod 755 /usr/local/sbin/custrep-ssh

# ---- 程序 ----
install -d -m755 "$L"
install -m755 "$SRC/custhub" /usr/local/sbin/custhub
install -m644 "$SRC/httpd.py" "$SRC/pool.py" "$L/"
install -m755 "$SRC/uninstall.sh" "$L/uninstall.sh"
mkdir -p "$S" "$W/j" "$W/pkg" "$R" "$P"
chmod 700 "$S"; chmod 755 "$W" "$W/j" "$W/pkg"
chown -R "$UW:$UW" "$R" "$P"; chmod 750 "$R"; chmod 700 "$P"   # 旧版回报目录属主是 nobody, 一并改
(umask 077; printf '%s\n' "$POOL_KEY" >"$P/pool.key"); chown "$UW:$UW" "$P/pool.key"
# 中枢身份(池里按它去重, 字段名沿用 srvpub): 旧版是 WG 公钥, 有就沿用; 新装取 32 字节随机数
[ -s "$S/server.pub" ] || head -c32 /dev/urandom | base64 >"$S/server.pub"
pyp(){ runuser -u "$UW" -- env POOL_DIR="$P" python3 -I "$L/pool.py" "$@"; }

# ---- 设置: 首次安装时定下, 之后以已存的为准(改网段/端口会让已接入客户失效) ----
NET= HOST= NAME= VERSION= REPO= WG_PORT=${WG_PORT:-} HTTP_PORT=${HTTP_PORT:-}
[ -f "$S/settings" ] && . "$S/settings"
probe=
if [ -n "$SEEDS" ] && { [ -z "$NET" ] || [ -z "$HOST" ]; }; then
  probe=$(runuser -u "$UW" -- env POOL_DIR="$P" python3 -I -c '
import sys,json; sys.path.insert(0,sys.argv[1]); import pool
for s in sys.argv[2:]:
    try: print(json.dumps(pool.hello(s,{"probe":True}))); break
    except Exception as e: print("probe",s,e,file=sys.stderr)' "$L" $SEEDS || true)
fi
if [ -z "$HOST" ]; then
  HOST=${HUB_HOST:-}
  [ -z "$HOST" ] && [ -n "$probe" ] && HOST=$(python3 -Ic 'import sys,json;print(json.loads(sys.argv[1])["you"])' "$probe" 2>/dev/null || true)
  for u in http://ip.3322.net http://myip.ipip.net/s https://api.ipify.org; do
    [ -n "$HOST" ] && break
    HOST=$(curl -4 -fsS -m6 "$u" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
  done
  [ -n "$HOST" ] || { echo "探测不到公网地址, 用 HUB_HOST=<公网IP> 再跑" >&2; exit 1; }
fi
if [ -z "$NET" ]; then
  # 每台中枢一个网段 10.89.k.0/24, 取池里没人用的最小 k
  NET=$(python3 -Ic '
import sys,json
used={m["net"] for m in (json.loads(sys.argv[1])["pool"] if sys.argv[1] else []) if not m.get("left")}
print(next("10.89.%d"%k for k in range(256) if "10.89.%d"%k not in used))' "$probe")
fi
[ -n "$NAME" ] || NAME=${HUB_NAME:-$(hostname -s | tr -cd 'A-Za-z0-9-' | cut -c1-24)}; NAME=${NAME:-hub}
WG_PORT=${WG_PORT:-51820}; HTTP_PORT=${HTTP_PORT:-8443}
# 版本/仓库: 由 bootstrap 传入, 供 Mac 远程升级时判断是否升好、从哪拉
VERSION=${CUSTHUB_REF:-$VERSION}; REPO=${CUSTHUB_REPO:-$REPO}
printf 'NET=%s\nWG_PORT=%s\nHTTP_PORT=%s\nHOST=%s\nNAME=%s\nVERSION=%s\nREPO=%s\n' "$NET" "$WG_PORT" "$HTTP_PORT" "$HOST" "$NAME" "$VERSION" "$REPO" >"$S/settings"
if ! systemctl is-active -q custhub-http 2>/dev/null && ss -lntH "sport = :$HTTP_PORT" | grep -q .; then say "警告: TCP $HTTP_PORT 已被别的程序占用"; fi

# 本机在池里的记录(字段变了才 ver+1, 免得别人收到无意义的更新)
SSH_PORT=$(sshd -T 2>/dev/null | awk '$1=="port" && !p{print $2; p=1}' || true); SSH_PORT=${SSH_PORT:-22}
[ -f /etc/ssh/ssh_host_ed25519_key.pub ] || ssh-keygen -q -A
python3 -I - "$P/self.json" "$NAME" "$HOST" "$WG_PORT" "$HTTP_PORT" "$(cat "$S/server.pub")" "$NET" "$SSH_PORT" "$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" <<'PY'
import sys,json,time
p,name,host,wg,http,pub,net,sshp,sshkey=sys.argv[1:]
new={"name":name,"host":host,"wg_port":int(wg),"http_port":int(http),"srvpub":pub,"net":net,"ssh_port":int(sshp),"sshkey":sshkey,"left":0}
try: old=json.load(open(p))
except Exception: old={}
same=all(old.get(k)==v for k,v in new.items())
new["joined"]=old.get("joined") or int(time.time())
# ver 用时间戳: 卸载会删掉 self.json, 重装若从 1 计数会小于池里留下的下线墓碑, 被别的中枢当旧记录丢掉(永远进不了池)
# 旧版是 1,2,3 计数(远小于时间戳), 升级时顺手迁到时间戳
ov=old.get("ver",0)
new["ver"]=ov if (same and ov>=1e9) else max(ov+1,int(time.time()))
json.dump(new,open(p,"w"))
PY
chown "$UW:$UW" "$P/self.json"

# ---- 管理账号: 只能跑 custhub + 端口转发; 出站被 nft 限死在本机回环(回拨口) ----
cat >/usr/local/sbin/custhub-ssh <<'EOF'
#!/bin/sh
# 管理账号的强制命令: 原样转给 custhub(由它做参数白名单校验); 跳板转发(ssh -J)不经过这里
set -f   # 不做通配符展开
exec sudo -n /usr/local/sbin/custhub $SSH_ORIGINAL_COMMAND
EOF
chmod 755 /usr/local/sbin/custhub-ssh
printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/custhub\n%s ALL=(root) NOPASSWD: /usr/local/sbin/custhub kick *, /usr/local/sbin/custhub kick-node *\n%s ALL=(root) NOPASSWD: /usr/local/sbin/custhub rep-in *\n' "$U" "$UT" "$UR" >/etc/sudoers.d/custhub; chmod 440 /etc/sudoers.d/custhub
install -d -m700 -o "$U" -g "$U" "/home/$U/.ssh"
echo "restrict,port-forwarding,command=\"/usr/local/sbin/custhub-ssh\" $ADMIN_KEY" >"/home/$U/.ssh/authorized_keys"
chown "$U:$U" "/home/$U/.ssh/authorized_keys"; chmod 600 "/home/$U/.ssh/authorized_keys"
if sshd -T -C "user=$U,host=x,addr=127.0.0.1" 2>/dev/null | grep -qiE '^allowtcpforwarding (no|remote)'; then
  say "警告: sshd 全局关了端口转发, 跳板用不了(要在 sshd_config 里给 $U 开 AllowTcpForwarding local)"
fi

# ---- 防火墙: 访问控制全在 nft inet custhub 表里 ----
cat >"$S/fw.nft" <<EOF
table inet custhub
delete table inet custhub
table inet custhub {
    chain output {
        type filter hook output priority -10; policy accept;
        meta skuid "$U" oifname "lo" accept
        meta skuid "$U" ct state established,related accept
        meta skuid "$U" reject
        meta skuid "$UT" ct state established,related accept
        meta skuid "$UT" reject
        meta skuid "$UR" ct state established,related accept
        meta skuid "$UR" reject
    }
}
EOF
nft -c -f "$S/fw.nft"
# nft 的 accept 只在本表生效: 宿主机若有别家的 INPUT DROP(ufw/firewalld/云镜像自带, iptables-nft 表), 照样会被丢。
# 探测到 iptables 才加放行, 没有就跳过; 只放中枢自己的 HTTP 端口
[ -x "$L/fw-passthru.sh" ] && "$L/fw-passthru.sh" stop   # 端口可能变过, 先撤旧规则
cat >"$L/fw-passthru.sh" <<EOF
#!/bin/sh
command -v iptables >/dev/null 2>&1 || exit 0
for r in "-p tcp --dport $HTTP_PORT"; do
    if [ "\$1" = stop ]; then iptables -D INPUT \$r -j ACCEPT 2>/dev/null
    else iptables -C INPUT \$r -j ACCEPT 2>/dev/null || iptables -I INPUT 1 \$r -j ACCEPT; fi
done
# 网络节点的公网端口(custhub node-set 开的), 开机/重装后补回
for p in \$(cat $S/node/* 2>/dev/null | sed -n 's/^port2\{0,1\}=//p'); do
    if [ "\$1" = stop ]; then iptables -D INPUT -p tcp --dport \$p -j ACCEPT 2>/dev/null
    else iptables -C INPUT -p tcp --dport \$p -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport \$p -j ACCEPT; fi
done
exit 0
EOF
chmod 755 "$L/fw-passthru.sh"

# ---- systemd ----
cat >/etc/systemd/system/custhub-fw.service <<EOF
[Unit]
Description=custhub firewall
After=network-pre.target nftables.service ufw.service firewalld.service docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $S/fw.nft
ExecStartPost=$L/fw-passthru.sh
ExecStop=$L/fw-passthru.sh stop
ExecStop=-/usr/sbin/nft delete table inet custhub

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/custhub-http.service <<EOF
[Unit]
Description=custhub http (scripts, packages, progress reports, pool)
After=network-online.target custhub-fw.service

[Service]
Environment=HTTP_PORT=$HTTP_PORT WEB_DIR=$W REPORT_DIR=$R POOL_DIR=$P
ExecStart=/usr/bin/python3 -I $L/httpd.py
User=$UW
Group=$UW
ReadOnlyPaths=$W
ReadWritePaths=$R $P
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/custhub-pool.service <<EOF
[Unit]
Description=custhub pool gossip
After=network-online.target custhub-http.service

[Service]
Type=oneshot
User=$UW
Environment=POOL_DIR=$P
ExecStart=/usr/bin/python3 -I $L/pool.py announce
EOF
cat >/etc/systemd/system/custhub-pool.timer <<EOF
[Unit]
Description=custhub pool gossip every 5 min

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
EOF

# 旧版的 WireGuard 加速通道(cust0)拆掉: 先去掉它对防火墙的依赖, 再停; 反向通道不受影响
if [ -e /etc/systemd/system/wg-quick@cust0.service.d ] || [ -f /etc/wireguard/cust0.conf ]; then
  rm -rf /etc/systemd/system/wg-quick@cust0.service.d; systemctl daemon-reload
  systemctl disable --now wg-quick@cust0 2>/dev/null || true; ip link del cust0 2>/dev/null || true
  rm -f /etc/wireguard/cust0.conf "$S/server.key"; rm -rf "$S/peers"
  say "已拆除旧的 WireGuard 加速通道(cust0)"
fi
systemctl daemon-reload
systemctl enable -q custhub-fw custhub-http custhub-pool.timer
# 防火墙: 在跑就直接重载规则(不必 restart, 免得规则有一瞬间是空的)
if systemctl is-active -q custhub-fw; then nft -f "$S/fw.nft" && "$L/fw-passthru.sh"; else systemctl start custhub-fw; fi
systemctl restart custhub-http
systemctl restart custhub-pool.timer
custhub tun-sync   # 按 tun/ 重写反向隧道授权
custhub rep-close 0000000000000000 >/dev/null 2>&1 || true   # 顺带按 rep/ 重写回报钥匙授权(清掉过期的)
sleep 1
systemctl is-active -q custhub-http custhub-fw || { say "服务没起来:"; systemctl --no-pager status custhub-http custhub-fw | tail -30; exit 1; }

# ---- 入池 ----
r=$(pyp announce $SEEDS 2>/dev/null | tail -1 || true)
n=$(pyp list | awk -F'\t' '$9=="0"' | wc -l)
say "完成: $NAME  $HOST  HTTP TCP $HTTP_PORT"
say "中枢池: 本次 ${r#reached } 台回应, 池内共 $n 台在册"
say "云服务器记得在安全组放行 TCP 22 和 TCP $HTTP_PORT"
code=$(python3 -Ic 'import sys,json,base64;print("CHR:"+base64.b64encode(json.dumps({"host":sys.argv[1],"http_port":int(sys.argv[2])}).encode()).decode())' "$HOST" "$HTTP_PORT")
say "登记码(池里没有别的活中枢时, 在 Mac 上跑 hub/add.sh 粘贴它):"
echo "$code"
