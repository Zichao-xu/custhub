#!/usr/bin/env python3
# pool.py — 中枢池: 中枢之间经公网 HTTP 互相报到、交换成员名单(无中心, 任意一台活着就能拿到全名单)
#   每台中枢的成员记录: name host wg_port http_port srvpub net joined ver left
#   合并规则: 同一 host 取 ver 大的那条(只有本人会改自己的记录, ver=改动时的时间戳, 重装后也一定更新; 下线= left=1 的墓碑, 30 天后清掉)
#   鉴权: 池密钥 HMAC-SHA256(ts + "\n" + body), 时间差 10 分钟内有效; 请求和应答都签
# 命令行(由 install.sh / 定时任务 / custhub 调用):
#   pool.py probe SEED...      向种子取名单(不登记自己), 输出 JSON {pool, you}
#   pool.py announce [SEED...] 把自己报给种子和名单上所有成员, 合并它们的名单
#   pool.py leave              墓碑自己并通知所有成员
#   pool.py list               本机名单 TSV: name host wg_port http_port srvpub net joined seen left ssh_port sshkey
import hashlib, hmac, json, os, sys, time, fcntl, urllib.request

P = os.environ.get("POOL_DIR", "/var/lib/custhub-pool")
SKEW = 600


def key():
    with open(os.path.join(P, "pool.key"), "rb") as f:
        return f.read().strip()


def sign(ts, body):
    return hmac.new(key(), ("%s\n" % ts).encode() + body, hashlib.sha256).hexdigest()


def check(ts, sig, body):
    try:
        if abs(time.time() - int(ts)) > SKEW:
            return False
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(sign(ts, body), sig or "")


def _load():
    try:
        with open(os.path.join(P, "pool.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def self_rec():
    with open(os.path.join(P, "self.json")) as f:
        return json.load(f)


FIELDS = ("name", "host", "wg_port", "http_port", "srvpub", "net", "joined", "ver", "left")


def clean(m):
    """只留已知字段并校验, 防止池里混进奇怪的数据"""
    try:
        r = {k: m[k] for k in FIELDS}
        assert isinstance(r["host"], str) and 3 < len(r["host"]) < 254 and all(c.isalnum() or c in ".-:" for c in r["host"])
        assert isinstance(r["name"], str) and 0 < len(r["name"]) < 64 and all(c.isalnum() or c in "-_." for c in r["name"])
        for k in ("wg_port", "http_port", "joined", "ver", "left"):
            r[k] = int(r[k])
        assert isinstance(r["srvpub"], str) and len(r["srvpub"]) == 44
        assert isinstance(r["net"], str) and r["net"].count(".") == 2
        # 反向隧道用(旧版中枢没有这两项)
        r["ssh_port"] = int(m.get("ssh_port") or 22)
        k = m.get("sshkey") or ""
        assert k == "" or (isinstance(k, str) and k.startswith("ssh-ed25519 ") and len(k) < 120 and all(c.isalnum() or c in " +/=-" for c in k))
        r["sshkey"] = k
        return r
    except Exception:
        return None


def merge(incoming):
    """把对方给的名单并进本机(加锁), 返回合并后的名单"""
    os.makedirs(P, exist_ok=True)
    with open(os.path.join(P, "pool.lock"), "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        pool = _load()
        me = self_rec()
        pool[me["host"]] = me  # 自己的记录永远以本机为准
        now = time.time()
        for m in incoming or []:
            m = clean(m)
            if not m or m["host"] == me["host"]:
                continue
            old = pool.get(m["host"])
            if not old or m["ver"] > old.get("ver", -1):
                m["seen"] = old.get("seen", 0) if old else 0
                pool[m["host"]] = m
        # 同一台中枢(服务器公钥相同)换了地址: 只留版本最新的那条
        best = {}
        for h, m in pool.items():
            b = best.get(m["srvpub"])
            if b is None or (m["host"] == me["host"]) or (pool[b]["host"] != me["host"] and m.get("ver", 0) > pool[b].get("ver", 0)):
                best[m["srvpub"]] = h
        for h in list(pool):
            if best.get(pool[h]["srvpub"]) != h:
                del pool[h]
        for h in list(pool):
            if pool[h].get("left") and now - pool[h].get("left", now) > 30 * 86400:
                del pool[h]
        tmp = os.path.join(P, "pool.json.tmp")
        with open(tmp, "w") as f:
            json.dump(pool, f)
        os.replace(tmp, os.path.join(P, "pool.json"))
        return pool


def mark_seen(host):
    with open(os.path.join(P, "pool.lock"), "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        pool = _load()
        if host in pool:
            pool[host]["seen"] = int(time.time())
            tmp = os.path.join(P, "pool.json.tmp")
            with open(tmp, "w") as f:
                json.dump(pool, f)
            os.replace(tmp, os.path.join(P, "pool.json"))


def hello(target, body_obj, timeout=8):
    """POST /pool/hello 到 target(host:port), 校验应答签名, 返回应答 JSON"""
    body = json.dumps(body_obj).encode()
    ts = str(int(time.time()))
    req = urllib.request.Request("http://%s/pool/hello" % target, data=body, method="POST",
                                 headers={"X-Ts": ts, "X-Sig": sign(ts, body), "Content-Type": "application/json"})
    # 不走系统代理: 中枢之间直连
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        data = r.read(1 << 20)
        if not check(r.headers.get("X-Ts"), r.headers.get("X-Sig"), data):
            raise RuntimeError("bad signature from %s" % target)
        return json.loads(data)


def serve_hello(remote_ip, body):
    """httpd 调: 处理一次报到; probe 不登记"""
    req = json.loads(body or b"{}")
    me = self_rec() if os.path.exists(os.path.join(P, "self.json")) else None
    if me and not req.get("probe") and req.get("self"):
        pool = merge([req["self"]])
    else:
        pool = _load()
        if me:
            pool[me["host"]] = me
    return json.dumps({"pool": list(pool.values()), "you": remote_ip}).encode()


def targets(extra):
    t = list(extra)
    me = self_rec()
    for m in _load().values():
        if m["host"] != me["host"] and not m.get("left"):
            t.append("%s:%s" % (m["host"], m["http_port"]))
    return list(dict.fromkeys(t))


def main(argv):
    cmd, args = (argv[0] if argv else ""), argv[1:]
    if cmd == "probe":
        for s in args:
            try:
                print(json.dumps(hello(s, {"probe": True})))
                return 0
            except Exception as e:
                print("probe %s: %s" % (s, e), file=sys.stderr)
        return 1
    if cmd in ("announce", "leave"):
        if cmd == "leave":
            me = self_rec()
            me["ver"] = max(me["ver"] + 1, int(time.time()))  # 与 install.sh 一致: ver=时间戳
            me["left"] = int(time.time())
            with open(os.path.join(P, "self.json"), "w") as f:
                json.dump(me, f)
        ok = 0
        for t in targets(args):
            try:
                r = hello(t, {"self": self_rec()})
                merge(r.get("pool"))
                mark_seen(t.rsplit(":", 1)[0])
                ok += 1
            except Exception as e:
                print("announce %s: %s" % (t, e), file=sys.stderr)
        merge([])
        print("reached %d" % ok)
        return 0
    if cmd == "list":
        for m in sorted(_load().values(), key=lambda m: (m.get("joined", 0), m["host"])):
            print("\t".join(str(m.get(k, "")) for k in ("name", "host", "wg_port", "http_port", "srvpub", "net", "joined", "seen", "left", "ssh_port", "sshkey")))
        return 0
    print(__doc__ or "usage: probe|announce|leave|list", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
