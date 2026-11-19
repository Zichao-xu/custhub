#!/usr/bin/env bash
# UPnP 自动映射验收(design-v3 §0 第 14 条), 本机多进程 + python 假路由器(不碰真路由器)
#   假路由器: 回 SSDP、给描述文件、收 AddPortMapping, 映射成功就真的把外部端口转发到节点
#   故意: 8444 被占(718) → 8445 只认永久映射(725) → 8445 永久映射成功
#   1 映射成功: 回连走映射出去的端口, 端口显示"已开启(UPnP 自动映射)"; 按租期续
#   2 没有路由器: 显示不通, 并提示跑命令的人怎么手动开
set -uo pipefail
cd "$(dirname "$0")"
./build.sh >/dev/null || exit 1
M=$PWD/mesh
T=$(mktemp -d); trap 'kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; [ -n "${KEEP:-}" ] && echo "现场: $T" || rm -rf "$T"' EXIT
pass=0; fail=0
ok(){ echo "  ✔ $*"; pass=$((pass+1)); }
ng(){ echo "  ✘ $*"; fail=$((fail+1)); }
wait_for(){ local s=$1; shift; for _ in $(seq $((s*4))); do "$@" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
base=$((20000 + RANDOM % 20000)); PR=$base PD=$((base+1)) PN=$((base+2)) SSDP=$((base+3)) HTTP=$((base+4))

python3 - "$SSDP" "$HTTP" >"$T/router.log" 2>&1 <<'PY' &
import socket, sys, threading, re, http.server
ssdp, hp = int(sys.argv[1]), int(sys.argv[2])
def say(*a): print(*a, flush=True)
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", ssdp))
    while True:
        d, a = s.recvfrom(2048)
        if b"M-SEARCH" in d:
            s.sendto(("HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://127.0.0.1:%d/desc.xml\r\n\r\n" % hp).encode(), a)
threading.Thread(target=udp, daemon=True).start()
fwd = {}
def forward(ext, inner):
    if ext in fwd: return
    l = socket.socket(); l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); l.bind(("127.0.0.1", ext)); l.listen(8); fwd[ext] = l
    def pipe(a, b):
        try:
            while True:
                x = a.recv(65536)
                if not x: break
                b.sendall(x)
        except OSError: pass
        for z in (a, b):
            try: z.shutdown(socket.SHUT_WR)
            except OSError: pass
    def acc():
        while True:
            c, _ = l.accept()
            u = socket.create_connection(("127.0.0.1", inner))
            threading.Thread(target=pipe, args=(c, u), daemon=True).start()
            threading.Thread(target=pipe, args=(u, c), daemon=True).start()
    threading.Thread(target=acc, daemon=True).start()
DESC = """<?xml version="1.0"?><root><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>"""
def fault(code): return """<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>%d</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>""" % code
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def out(self, code, body):
        b = body.encode(); self.send_response(code); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self): self.out(200, DESC)
    def do_POST(self):
        x = self.rfile.read(int(self.headers["Content-Length"])).decode()
        g = lambda t: re.search("<%s>(.*?)</%s>" % (t, t), x).group(1)
        ext, inner, lease, cli = int(g("NewExternalPort")), int(g("NewInternalPort")), int(g("NewLeaseDuration")), g("NewInternalClient")
        if ext == 8444: say("map", ext, inner, lease, cli, "-> 718"); return self.out(500, fault(718))
        if lease != 0: say("map", ext, inner, lease, cli, "-> 725"); return self.out(500, fault(725))
        say("map", ext, inner, lease, cli, "-> ok"); forward(ext, inner); self.out(200, "<ok/>")
http.server.ThreadingHTTPServer(("127.0.0.1", hp), H).serve_forever()
PY
sleep 0.5

ssh-keygen -q -t ed25519 -N '' -C master -f "$T/master"
for n in r d n; do mkdir -p "$T/$n"; $M keygen "$T/$n" >"$T/$n.pub"; done
{ echo "custhub-mesh-trust 1"; echo "relay r $(cat "$T/r.pub") 127.0.0.1:$PR"; echo "node d $(cat "$T/d.pub")"; echo "node n $(cat "$T/n.pub")"; echo "--end--"; } >"$T/data"
ssh-keygen -q -Y sign -f "$T/master" -n custhub-mesh-trust "$T/data" 2>/dev/null; cat "$T/data" "$T/data.sig" >"$T/trust"
i=0; for n in r d n; do i=$((i+1))
  printf 'master %s\nctl 127.0.0.1:%s\nlog %s\n' "$(cat "$T/master.pub")" $((base+10+i)) "$T/$n.log" >"$T/$n/conf"; cp "$T/trust" "$T/$n/trust"
done
echo "upnp off" >>"$T/r/conf"; echo "listen 127.0.0.1:$PD" >>"$T/d/conf"; printf 'listen 127.0.0.1:%s\nannounce 127.0.0.1:1\n' $PN >>"$T/n/conf"   # 同一台机器上本来就连得到: 报一个连不进来的地址, 才测得到"不通"
$M run "$T/r" 2>/dev/null &
CUSTHUB_UPNP_SSDP=127.0.0.1:$SSDP CUSTHUB_UPNP_RENEW_S=3 CUSTHUB_MESH_PROBE_S=2 $M run "$T/d" 2>/dev/null &
CUSTHUB_UPNP_SSDP=127.0.0.1:1 CUSTHUB_MESH_PROBE_RETRY_S=2 $M run "$T/n" 2>/dev/null &      # 没有路由器

echo "== 1 有 UPnP 的路由器"
wait_for 15 sh -c "$M ls $T/d | grep -q 'UPnP 自动映射'"
grep -q "map 8444 $PD 3600 127.0.0.1 -> 718" "$T/router.log" && ok "先要外部 8444, 被占(718)" || ng "没先试 8444: $(cat "$T/router.log")"
grep -q "map 8445 $PD 3600 .* -> 725" "$T/router.log" && grep -q "map 8445 $PD 0 .* -> ok" "$T/router.log" && ok "换 8445; 路由器只认永久映射(725)就改用永久, 成功" || ng "718/725 处理不对: $(cat "$T/router.log")"
grep -q "UPnP: 路由器上已把 TCP 8445 映射到本机 127.0.0.1:$PD" "$T/d.log" && ok "日志写明映射了什么" || ng "d 日志里没有映射记录"
o=$($M ls "$T/d" | grep "端口")
echo "$o" | grep -q "已开启(UPnP 自动映射): 127.0.0.1:8445" && ok "回连走映射出去的端口, 端口显示已开启: ${o#端口: }" || ng "端口: [$o]"
sleep 4
[ "$(grep -c "map 8445 $PD 0 .* -> ok" "$T/router.log")" -ge 2 ] && ok "按租期续了映射" || ng "没续租: $(grep -c ok "$T/router.log")"

echo "== 2 没有路由器"
wait_for 15 sh -c "$M ls $T/n | grep -q '不通'"
grep -q "UPnP: 没映射上(局域网里没找到支持 UPnP 的路由器)" "$T/n.log" && ok "找不到路由器: 日志说明原因" || ng "n 日志: $(grep UPnP "$T/n.log")"
o=$($M ls "$T/n" | grep "端口")
echo "$o" | grep -q "请在路由器上把 TCP $PN 映射到 .*:$PN(可选, 不开也能接入)" && ok "提示跑命令的人怎么手动开" || ng "提示: [$o]"

echo "== 结果: 通过 $pass, 失败 $fail"
[ $fail = 0 ]
