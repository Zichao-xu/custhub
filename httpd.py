#!/usr/bin/env python3
# 中枢 HTTP: 下发一次性接入脚本(/j)、安装包(/pkg)、收客户端进度回报(/cgi-bin/report)。
# 走 http 不走 https: Win7 自带 PowerShell 2.0 没有 TLS1.2; 下发内容里没有任何密钥(隧道私钥在客户机本地生成)。
#   GET  /cgi-bin/report?t=<码>&s=<步骤>&m=<说明>[&u=<用户>&h=<机器名>]  → <码>.log 追加一行; s=done 另写 <码>.done
#   POST /cgi-bin/report?t=<码>   正文=失败日志尾 → <码>.fail(上限 24KB)
#   POST /pool/hello              中枢之间互相报到/交换名单(池密钥签名, 见 pool.py)
# 只认 /j 下还存在的码; 值保持 URL 编码原样落盘(Mac 侧解码), 只留安全字符。
import os, re, sys, time, shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pool

W = os.environ.get("WEB_DIR", "/srv/custhub")
R = os.environ.get("REPORT_DIR", "/var/lib/custhub-report")
PORT = int(os.environ.get("HTTP_PORT", "51880"))
TOK = re.compile(r"^[0-9a-f]{16,64}$")
SAFE = re.compile(r"[^A-Za-z0-9._%+/()!*~-]")
MSG = "这条远程维护命令已过期，请向工程师重新获取一条。"
# PS2 的 DownloadString 按系统 ANSI 码页解码(中文 Windows=GBK), 中文用 [char] 拼, 响应保持纯 ASCII
_ps = "+".join("[char]0x%04x" % ord(c) for c in MSG)
EXPIRED_PS = ("$m=" + _ps + "; Add-Type -AssemblyName System.Windows.Forms; "
              "[void][Windows.Forms.MessageBox]::Show($m, 'Remote', 'OK', 'Warning'); [Environment]::Exit(0)\n").encode()
EXPIRED_SH = ("osascript -e 'display alert \"%s\"' >/dev/null 2>&1; echo '%s'\n" % (MSG, MSG)).encode()


def field(q, k):
    for kv in q.split("&"):
        if kv.startswith(k + "="):
            return SAFE.sub("", kv[len(k) + 1:])[:1500]
    return ""


class H(BaseHTTPRequestHandler):
    server_version = "custhub"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *a):  # 只记错误, 别把每个安装包请求刷进日志
        if a and str(a[1])[:1] in "45":
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

    def send(self, code, body=b"", ctype="text/plain", signed=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if signed:
            ts = str(int(time.time()))
            self.send_header("X-Ts", ts)
            self.send_header("X-Sig", pool.sign(ts, body))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def token(self, q):
        t = field(q, "t")
        return t if TOK.match(t) and os.path.isfile(os.path.join(W, "j", t + ".ps1")) else None

    def do_GET(self):
        path, _, q = self.path.partition("?")
        if path == "/cgi-bin/report":
            t = self.token(q)
            if not t:
                return self.send(200, b"no\n")
            s = field(q, "s")
            if s:
                with open(os.path.join(R, t + ".log"), "a") as f:
                    f.write("%d %s %s\n" % (time.time(), s, field(q, "m")))
            if s == "done":
                with open(os.path.join(R, t + ".done"), "w") as f:
                    f.write("%s %s\n" % (field(q, "u"), field(q, "h")))
            return self.send(200, b"ok\n")
        m = re.match(r"^/j/([0-9a-f]{16,64})\.(ps1|sh)$", path)
        if m and not os.path.isfile(os.path.join(W, "j", path[3:])):
            # 过期/作废的码: 客户机窗口是隐藏的, 不提示就是"什么都没发生", 弹个框让客户知道要重新要命令
            return self.send(200, EXPIRED_PS if m.group(2) == "ps1" else EXPIRED_SH)
        if not (path.startswith("/j/") or path.startswith("/pkg/")) or ".." in path:
            return self.send(404)
        full = os.path.realpath(os.path.join(W, path.lstrip("/")))
        if not full.startswith(os.path.realpath(W) + "/") or not os.path.isfile(full):
            return self.send(404)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(os.path.getsize(full)))
        self.end_headers()
        if self.command != "HEAD":
            with open(full, "rb") as f:
                shutil.copyfileobj(f, self.wfile, 256 * 1024)

    do_HEAD = do_GET

    def do_POST(self):
        path, _, q = self.path.partition("?")
        if path == "/pool/hello":
            n = int(self.headers.get("Content-Length") or 0)
            if n > (1 << 20):
                return self.send(413)
            body = self.rfile.read(n)
            try:
                if not pool.check(self.headers.get("X-Ts"), self.headers.get("X-Sig"), body):
                    return self.send(403)
                return self.send(200, pool.serve_hello(self.client_address[0], body), "application/json", signed=True)
            except Exception as e:
                sys.stderr.write("pool hello: %r\n" % e)
                return self.send(400)
        t = self.token(q) if path == "/cgi-bin/report" else None
        if not t:
            return self.send(200, b"no\n")
        n = min(int(self.headers.get("Content-Length") or 0), 24576)
        with open(os.path.join(R, t + ".fail"), "wb") as f:
            f.write(self.rfile.read(n))
        self.send(200, b"ok\n")


if __name__ == "__main__":
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
