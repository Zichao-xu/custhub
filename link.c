/* 链路: TCP + Noise IK; 线上格式 [2 字节长度][Noise 消息]; 握手后每条消息是一帧 [类型 1][流号 4][内容]
 * 节点出站挂名单里的可达节点; 可达节点还接受入站, 并且互相挂(两条重复链路按"发起方公钥小的留下")
 * 握手第一条的内容(加密)= "custhub-mesh/版本 <ed25519 公钥> <自报信息>": 可达节点据此把名单外的节点记进待批准 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

g_t G;
static const char HELLO[] = "custhub-mesh/" MESH_VER;
/* 还没批准时多久再报到一次(报到时才拿得到新名单): 启动后头 15 分钟每 15 秒(跑接入命令的人正等着), 之后 10 分钟
 * 环境变量 CUSTHUB_MESH_PENDING_S 可固定成别的秒数(测试用) */
static int64_t pending_backoff(void)
{
    static int64_t t0;
    if (!t0) t0 = now_ms();
    const char *e = getenv("CUSTHUB_MESH_PENDING_S");
    long v = e ? atol(e) : 0;
    if (v > 0 && v < 3600) return v * (int64_t)1000;
    return now_ms() - t0 < 15 * 60000 ? 15000 : 600000;
}
#define PENDING_BACKOFF pending_backoff()

static int conn_alloc(int fd, int initiator)
{
    for (int i = 0; i < MAXC; i++) if (G.c[i].state == C_FREE) {
        conn_t *c = &G.c[i];
        memset(c, 0, sizeof *c);
        c->fd = fd; c->initiator = initiator; c->target = -1;
        c->born = c->last_rx = c->last_tx = now_ms();
        c->next_sid = initiator ? 1 : 2;          /* 两端各用奇偶, 不撞号 */
        return i;
    }
    return -1;
}

int addr_fam(const char *a) { return a && a[0] == '[' ? 6 : 4; }

int local_ip6(char *out, size_t cap)
{
    const char *e = getenv("CUSTHUB_IP6");
    if (e) { snprintf(out, cap, "%s", e); return *e ? 0 : -1; }
    return p_local_ip6(out, cap);
}

int conn_by_peer_fam(const uint8_t ed[32], int fam)
{
    int best = -1;
    for (int i = 0; i < MAXC; i++)
        if (G.c[i].state == C_UP && !memcmp(G.c[i].peer, ed, 32) && (!fam || G.c[i].fam == fam) && (best < 0 || G.c[i].born > G.c[best].born)) best = i;
    return best;
}

/* 双栈热备: 两种都通时新流量走 IPv6, IPv6 断了马上落到 IPv4(已在跑的流留在原链路上) */
int conn_by_peer(const uint8_t ed[32])
{
    int k = conn_by_peer_fam(ed, 6);
    return k >= 0 ? k : conn_by_peer_fam(ed, 4);
}

uint32_t conn_new_sid(int i) { uint32_t s = G.c[i].next_sid; G.c[i].next_sid += 2; return s; }

static int raw_send(conn_t *c, const uint8_t *m, size_t n)
{
    uint8_t h[2] = { (uint8_t)(n >> 8), (uint8_t)n };
    if (buf_add(&c->out, h, 2) || buf_add(&c->out, m, n)) return -1;
    c->last_tx = now_ms();
    return 0;
}

int conn_send(int i, int type, uint32_t sid, const void *pl, size_t n)
{
    conn_t *c = &G.c[i];
    if (c->state != C_UP || n > MAXMSG - 5 - 16) return -1;
    static uint8_t f[MAXMSG], ct[MAXMSG];
    f[0] = (uint8_t)type;
    f[1] = (uint8_t)(sid >> 24); f[2] = (uint8_t)(sid >> 16); f[3] = (uint8_t)(sid >> 8); f[4] = (uint8_t)sid;
    if (n) memcpy(f + 5, pl, n);
    long cn = cs_seal(&c->tx, f, n + 5, ct);
    if (raw_send(c, ct, (size_t)cn)) return -1;
    if (c->out.len > OUTDROP) { conn_close(i, "发送积压过多"); return -1; }
    return 0;
}

void conn_close(int i, const char *why)
{
    conn_t *c = &G.c[i];
    if (c->state == C_FREE) return;
    if (c->state == C_UP && !c->closing && (member_by_ed(G.id.ed) || c->guest)) logf_("链路断开 %s: %s", name_of(c->peer), why);
    int pending = c->initiator && !member_by_ed(G.id.ed) && !c->guest;
    for (int t = 0; t < G.nt; t++) if (G.t[t].conn6 == i) {
        G.t[t].conn6 = -1; snprintf(G.t[t].why6, sizeof G.t[t].why6, "%s", why); G.t[t].next6 = now_ms() + G.t[t].back6;
    }
    for (int t = 0; t < G.nt; t++) if (G.t[t].conn == i) {
        target_t *tg = &G.t[t];
        tg->conn = -1;
        snprintf(tg->why, sizeof tg->why, "%s", pending ? "已报到, 等批准" : why);
        tg->next_try = now_ms() + (pending ? PENDING_BACKOFF : tg->backoff);   /* 退避在 dial 里已经翻倍过 */
        if (pending) logf_("已向 %s 报到, 等批准(%lld 秒后再报)", tg->name, (long long)(PENDING_BACKOFF / 1000));
    }
    if (c->probe_for && c->state != C_UP) {            /* 替别人测端口: 没连通 */
        int f = c->probe_for - 1; char m[140];
        snprintf(m, sizeof m, "no %s", why);
        if (G.c[f].state == C_UP) conn_send(f, F_PROBEA, 0, m, strlen(m));
        if (G.c[f].closing == 3) conn_finish(f);
    }
    if (G.probing && G.probe_conn == i) { G.probing = 0; if (G.probe_fam == 6) G.probe6_next = 0; else G.probe_next = 0; }   /* 回连测试请求跟着这条链路丢了: 马上换一条再请 */
    int was_up = c->state == C_UP;
    c->state = C_FREE;
    if (was_up) hop_conn_down(i);
    p_close(c->fd);
    buf_free(&c->in); buf_free(&c->out);
    memset(&c->hs, 0, sizeof c->hs); memset(&c->tx, 0, sizeof c->tx); memset(&c->rx, 0, sizeof c->rx);
}

/* 报到 / 测试链路收尾: 发完已排队的就半关(缓冲已空时 conn_write 不会再被叫到, 要在这里关) */
void conn_finish(int i)
{
    conn_t *c = &G.c[i];
    if (c->state != C_UP) return;
    c->closing = 1;
    if (!c->out.len) { p_shut_wr(c->fd); c->closing = 2; }
}

/* 同一对端同一种协议有两条链路: 双方各拨一条时留"发起方公钥小的那条", 同一方拨了两条留新的 */
static void dedupe(int i)
{
    conn_t *c = &G.c[i];
    for (int j = 0; j < MAXC; j++) {
        if (j == i || G.c[j].state != C_UP || memcmp(G.c[j].peer, c->peer, 32) || G.c[j].fam != c->fam) continue;   /* v4、v6 各留一条 */
        int drop = j;
        if (c->initiator != G.c[j].initiator) {        /* 双方各拨了一条: 两边按同一规则留, 不看当不算可达(否则两边各删一条, 反复重连) */
            int me_small = memcmp(G.id.ed, c->peer, 32) < 0;
            int keep_mine = me_small;                 /* 公钥小的一方发起的那条留下 */
            drop = (c->initiator == keep_mine) ? j : i;
        }
        conn_close(drop, "重复链路");
        if (drop == i) return;
    }
}

static void on_up(int i)
{
    conn_t *c = &G.c[i];
    c->state = C_UP;
    c->peer_relay = c->pm ? ed_relay(c->peer) : 0;
    if (!member_by_ed(G.id.ed) && !c->guest) {         /* 本机还没被批准也没通行证: 这条链路只是报到, 等可达节点发来名单后断开 */
        if (G.relay_off || G.lfd < 0) conn_send(i, F_PROBE, 0, "-", 1);   /* 本机不算可达: 告诉可达节点不用等回连测试请求 */
        return;
    }
    logf_("链路建立 %s(%s, %s%s)", name_of(c->peer), c->initiator ? "出站" : "入站", c->addr, c->guest ? ", 访客" : "");
    for (int t = 0; t < G.nt; t++) if (G.t[t].conn == i) { G.t[t].backoff = 1000; snprintf(G.t[t].why, sizeof G.t[t].why, "up"); }
    for (int t = 0; t < G.nt; t++) if (G.t[t].conn6 == i) { G.t[t].back6 = 1000; snprintf(G.t[t].why6, sizeof G.t[t].why6, "up"); }
    G.last_up_ms = now_ms();
    dedupe(i);
    if (c->state == C_UP) disc_on_up(i);
}

static void on_frame(int i, const uint8_t *f, size_t n)
{
    if (n < 5) { conn_close(i, "帧太短"); return; }
    int type = f[0];
    uint32_t sid = (uint32_t)f[1] << 24 | (uint32_t)f[2] << 16 | (uint32_t)f[3] << 8 | f[4];
    const uint8_t *pl = f + 5; size_t pn = n - 5;
    switch (type) {
    case F_PING:  conn_send(i, F_PONG, 0, NULL, 0); break;
    case F_PONG:  break;
    case F_REC:   disc_rec_in(i, (const char *)pl, pn); break;
    case F_TRUST: mtrust_apply((const char *)pl, pn, name_of(G.c[i].peer)); break;
    case F_PENDQ: disc_pendq(i, pl, pn); break;
    case F_PENDA: disc_penda(i, pl, pn); break;
    case F_PROBE: qual_probe_in(i, pl, pn); break;
    case F_PROBEA: qual_probe_ans(i, pl, pn); break;
    default:      hop_frame(i, type, sid, pl, pn); break;
    }
}

/* 名单外节点报到: 握手内容里自带 ed25519 公钥(须与握手证明的 x25519 对得上)和自报信息, 记进 <目录>/pending */
static void note_pending(conn_t *c, const uint8_t *pl, long n)
{
    char t[300], ver[40] = "", edb[64] = "", info[200] = "";
    if (n <= 0 || n >= (long)sizeof t) return;
    memcpy(t, pl, (size_t)n); t[n] = 0;
    if (sscanf(t, "%39s %63s %199[^\n]", ver, edb, info) < 2) return;
    uint8_t ed[32], x[32];
    if (b64_decode(edb, strlen(edb), ed, 32) != 32) return;
    ed_to_x(ed, x);
    if (memcmp(x, c->hs.rs, 32)) { logf_("报到的公钥对不上握手身份(来自 %s), 不记", c->addr); return; }
    for (char *p = info; *p; p++) if ((unsigned char)*p < 0x20) *p = '_';
    char path[300], old[16384], line[512], out[16384] = "";
    snprintf(path, sizeof path, "%s/pending", G.dir);
    long on = m_read(path, old, sizeof old);
    size_t ol = 0; int count = 0;
    if (on > 0) {   /* 同一公钥只留最新一行, 最多 100 行 */
        char *save = NULL;
        for (char *l = m_tok(old, "\n", &save); l; l = m_tok(NULL, "\n", &save)) {
            if (!strncmp(l, edb, strlen(edb)) && l[strlen(edb)] == ' ') continue;
            if (++count > 99) break;
            ol += (size_t)snprintf(out + ol, sizeof out - ol, "%s\n", l);
            if (ol >= sizeof out - 600) break;
        }
    }
    int ln = snprintf(line, sizeof line, "%s %lld %s %s\n", edb, (long long)(wall_ms() / 1000), c->addr, info[0] ? info : "-");
    if (ol + (size_t)ln < sizeof out) { memcpy(out + ol, line, (size_t)ln); ol += (size_t)ln; }
    m_write(path, out, ol);
    logf_("待批准: %s(%s, 来自 %s)", edb, info[0] ? info : "-", c->addr);
}

/* 名单外节点出示通行证(握手第一条内容的第二行起): 验过就当访客接入, 只帮它转到通行证 to 里的机器 */
static int guest_admit(conn_t *c, const uint8_t *pl, long n)
{
    char why[80], edb[64] = "", ver[40] = "";
    const char *nl = memchr(pl, '\n', (size_t)n);
    if (!nl) return 0;
    if (sscanf((const char *)pl, "%39s %63s", ver, edb) != 2) return 0;
    uint8_t ed[32], x[32];
    if (b64_decode(edb, strlen(edb), ed, 32) != 32) return 0;
    ed_to_x(ed, x);
    if (memcmp(x, c->hs.rs, 32)) return 0;
    if (pass_parse(nl + 1, (size_t)(n - (nl + 1 - (const char *)pl)), G.master, &c->gp, why, sizeof why) ||
        pass_allows(&c->gp, ed, NULL, NULL, wall_ms() / 1000, why, sizeof why)) {
        logf_("访客 ?%.8s 的通行证不行(%s), 按报到处理", edb, why);
        return 0;
    }
    c->guest = 1; c->pm = NULL; memcpy(c->peer, ed, 32);
    return 1;
}

static void on_msg(int i, uint8_t *m, size_t n)
{
    conn_t *c = &G.c[i];
    static uint8_t out[MAXMSG], pl[MAXMSG];
    if (c->state == C_HS && !c->initiator) {            /* 应答方收到第一条 */
        long r = hs_read1(&c->hs, m, n, pl, sizeof pl);
        if (r < 0) { conn_close(i, "握手失败"); return; }
        member_t *pm = member_by_x(c->hs.rs);
        if (pm && r >= 6 && !memcmp(pl + r - 6, " probe", 6)) {   /* 成员拨过来测本机端口: 握手证明了就是本机, 回完就断 */
            long w = hs_write2(&c->hs, (const uint8_t *)HELLO, sizeof HELLO - 1, out, &c->tx, &c->rx);
            raw_send(c, out, (size_t)w);
            c->state = C_UP; c->closing = 1; c->probe_in = 1; c->pm = pm; memcpy(c->peer, pm->ed, 32);
            return;
        }
        if (!pm && (G.me_relay || me_seed()) && guest_admit(c, pl, r)) {   /* 种子还没自检通过也收报到 / 访客(转发仍要过自检) */
            static const char GH[] = "custhub-mesh/" MESH_VER " guest";
            long w = hs_write2(&c->hs, (const uint8_t *)GH, sizeof GH - 1, out, &c->tx, &c->rx);
            raw_send(c, out, (size_t)w);
            on_up(i);
            return;
        }
        if (!pm) {
            if (!G.me_relay && !me_seed()) { conn_close(i, "不在名单"); return; }
            /* 名单外节点报到: 记下, 握手做完, 把当前名单发给它, 发完就断(它被批准后拿这份名单就能正式接入) */
            note_pending(c, pl, r);
            long w = hs_write2(&c->hs, (const uint8_t *)HELLO, sizeof HELLO - 1, out, &c->tx, &c->rx);
            raw_send(c, out, (size_t)w);
            c->state = C_UP; c->closing = 3; c->pm = NULL; memset(c->peer, 0, 32);   /* 等它的回连测试请求(最多 15 秒) */
            conn_send(i, F_TRUST, 0, G.trust.text, G.trust.tlen);
            return;
        }
        c->pm = pm; memcpy(c->peer, pm->ed, 32);
        long w = hs_write2(&c->hs, (const uint8_t *)HELLO, sizeof HELLO - 1, out, &c->tx, &c->rx);
        raw_send(c, out, (size_t)w);
        on_up(i);
        return;
    }
    if (c->state == C_HS) {                             /* 发起方收到回应 */
        long r = hs_read2(&c->hs, m, n, pl, sizeof pl, &c->tx, &c->rx);
        if (r < 0) { conn_close(i, "握手失败(对方钥匙不对)"); return; }
        if (c->probe_for) {                              /* 替别人测端口: 握手成功 = 那个地址连得进来、确实是它 */
            int f = c->probe_for - 1; char m[100];
            snprintf(m, sizeof m, "ok %s", c->addr);
            if (G.c[f].state == C_UP) conn_send(f, F_PROBEA, 0, m, strlen(m));
            if (G.c[f].closing == 3) conn_finish(f);
            c->probe_for = 0; c->state = C_UP;
            conn_close(i, "回连测试完成");
            return;
        }
        if (!member_by_ed(G.id.ed) && r >= 6 && !memcmp(pl + r - 6, " guest", 6)) c->guest = 1;   /* 可达节点认了本机的通行证 */
        on_up(i);
        return;
    }
    if (c->closing == 1) return;                        /* 发完就断的链路: 对方发什么都不理 */
    long r = cs_open(&c->rx, m, n, pl);
    if (r < 0) { conn_close(i, "解密失败"); return; }
    c->last_rx = now_ms();
    if (c->closing == 3) {                              /* 报到链路: 只收回连测试请求 */
        if (r >= 5 && pl[0] == F_PROBE) qual_probe_in(i, pl + 5, (size_t)r - 5);
        return;
    }
    on_frame(i, pl, (size_t)r);
}

static const void *memmem_(const void *h, size_t hn, const void *n, size_t nn)
{
    for (size_t i = 0; i + nn <= hn; i++) if (!memcmp((const char *)h + i, n, nn)) return (const char *)h + i;
    return NULL;
}

static void conn_read(int i)
{
    conn_t *c = &G.c[i];
    static uint8_t tmp[65536];
    long r = p_recv(c->fd, tmp, sizeof tmp);
    if (r == 0) { conn_close(i, "对方关闭"); return; }
    if (r == P_AGAIN) return;
    if (r < 0) { conn_close(i, p_strerr(p_lasterr())); return; }
    c->last_rx = now_ms();
    if (buf_add(&c->in, tmp, (size_t)r)) { conn_close(i, "内存不足"); return; }
    if (c->state == C_HS && !c->initiator && c->in.len >= 4 && !memcmp(c->in.p, "GET ", 4)) {   /* 普通 HTTP 下载(rel.c): 握手第一条的长度头不会是 "GE" */
        if (c->in.len > 4096) { conn_close(i, "HTTP 请求太长"); return; }
        if (!memmem_(c->in.p, c->in.len, "\r\n\r\n", 4) && !memmem_(c->in.p, c->in.len, "\n\n", 2)) return;   /* 等请求头收齐 */
        static char rq[4097]; size_t rn = c->in.len; memcpy(rq, c->in.p, rn); rq[rn] = 0;
        int fd = c->fd; c->fd = -1;
        conn_close(i, "HTTP");
        http_take(fd, rq, rn);
        return;
    }
    size_t off = 0;
    while (c->state != C_FREE && c->in.len - off >= 2) {
        size_t n = (size_t)c->in.p[off] << 8 | c->in.p[off + 1];
        if (c->in.len - off - 2 < n) break;
        on_msg(i, c->in.p + off + 2, n);
        off += 2 + n;
    }
    if (c->state != C_FREE) buf_eat(&c->in, off);
}

static void conn_write(int i)
{
    conn_t *c = &G.c[i];
    if (c->state == C_CONNECTING) {
        int err = p_dial_result(c->fd);
        if (err) { conn_close(i, p_strerr(err)); return; }
        c->state = C_HS;
        static uint8_t m1[PASSMAX + 512];
        static char pl[PASSMAX + 300]; char edb[48];
        b64_encode(G.id.ed, 32, edb);
        int pn = snprintf(pl, sizeof pl, "%s %s %s", HELLO, edb, c->probe_for ? "probe" : G.hello[0] ? G.hello : G.name);
        if (!member_by_ed(G.id.ed) && !c->probe_for) {                    /* 名单外: 有通行证就附上, 可达节点认了就以访客身份接入 */
            pl[pn++] = '\n';
            int k = pass_load(NULL, NULL, pl + pn, sizeof pl - (size_t)pn);
            if (k) pn += k; else pn--;
        }
        long n = hs_write1(&c->hs, (const uint8_t *)pl, (size_t)pn, m1);
        raw_send(c, m1, (size_t)n);
    }
    while (c->out.len) {
        long w = p_send(c->fd, c->out.p, c->out.len);
        if (w == P_AGAIN) return;
        if (w < 0) { conn_close(i, p_strerr(p_lasterr())); return; }
        buf_eat(&c->out, (size_t)w);
    }
    /* 报到链路: 名单发完先半关, 等对方关或 5 秒后收(直接 close 可能把还没读完的数据变成 RST) */
    if (c->closing == 1 && !c->out.len) { p_shut_wr(c->fd); c->closing = 2; }
}

static void dial(int t, int six)
{
    target_t *tg = &G.t[t];
    char host[64]; int port;
    char *why = six ? tg->why6 : tg->why; size_t wc = six ? sizeof tg->why6 : sizeof tg->why;
    const char *addr;
    if (six) {
        tg->next6 = now_ms() + tg->back6; tg->back6 = tg->back6 < 8000 ? tg->back6 * 2 : 8000;
        addr = tg->addr6;
    } else {
        /* 多端点: 自报地址、地址簿 / 老名单、对方报的各局域网端点, 轮流试(跳过本机自己的地址), 通了就留下 */
        const char *cand[8]; int nc = 0;
        if (tg->addr[0]) cand[nc++] = tg->addr;
        if (tg->alt[0]) cand[nc++] = tg->alt;
        static char mine[16][48]; static int nmine; static int64_t mine_at;
        if (!mine_at || now_ms() - mine_at > 30000) { mine_at = now_ms(); nmine = p_local_ipv4s(mine, 16); }
        for (int k = 0; k < tg->nep && nc < 8; k++) {
            char h[64]; int pp, own = 0;
            if (hostport(tg->ep[k], h, sizeof h, &pp)) continue;
            char lh[64]; int lp = 0;                        /* 本机自己的地址 + 本机监听端口 = 拨到自己, 跳过 */
            if (!hostport(G.lspec, lh, sizeof lh, &lp)) for (int j = 0; j < nmine; j++) if (!strcmp(mine[j], h) && pp == lp) own = 1;
            if (!own) cand[nc++] = tg->ep[k];
        }
        int cap = tg->direct ? 60000 : 8000;            /* 只有局域网端点的(多半不在同一局域网): 退避放长 */
        if (!nc) { tg->next_try = now_ms() + cap; snprintf(why, wc, "没有能试的地址"); return; }
        int round = tg->flip++ % nc;
        addr = cand[round];
        if (round + 1 < nc) tg->next_try = now_ms() + 1000;   /* 这一轮还有没试的: 一秒后试下一个 */
        else { tg->next_try = now_ms() + tg->backoff; tg->backoff = tg->backoff < cap ? tg->backoff * 2 : cap; }
    }
    if (hostport(addr, host, sizeof host, &port)) { snprintf(why, wc, "地址不对: %s", addr); return; }
    int fd = p_dial(host, port, 1, why, wc);
    if (fd < 0) return;
    int i = conn_alloc(fd, 1);
    if (i < 0) { p_close(fd); return; }
    conn_t *c = &G.c[i];
    c->state = C_CONNECTING; c->target = t; c->fam = addr_fam(addr);
    snprintf(c->addr, sizeof c->addr, "%s", addr);
    member_t *pm = member_by_ed(tg->ed);
    if (!pm) { conn_close(i, "名单里没有"); return; }
    c->pm = pm; memcpy(c->peer, tg->ed, 32);
    hs_init(&c->hs, 1, G.id.xsec, G.id.x, pm->x);
    if (six) tg->conn6 = i; else tg->conn = i;
}

/* 可达节点接受一条入站链路; fd 也可以由别的程序递进来(中转 8443 上按第一个字节分流后转给我们) */
static void take_inbound(int fd, const char *addr)
{
    p_nb(fd);
    int i = conn_alloc(fd, 0);
    if (i < 0) { p_close(fd); return; }
    G.c[i].state = C_HS; G.c[i].fam = addr_fam(addr);
    snprintf(G.c[i].addr, sizeof G.c[i].addr, "%s", addr);
    hs_init(&G.c[i].hs, 0, G.id.xsec, G.id.x, NULL);
}

static void do_accept(int lfd)
{
    char a[80];
    int fd = p_accept(lfd, a, sizeof a);
    if (fd >= 0) take_inbound(fd, a);
}

int listen_on(const char *spec)
{
    char host[64]; int port;
    if (hostport(spec, host, sizeof host, &port)) return -1;
    return p_listen(host, port);
}

static void tick(void)
{
    int64_t now = now_ms();
    for (int i = 0; i < MAXC; i++) {
        conn_t *c = &G.c[i];
        if (c->state == C_FREE) continue;
        if (c->state != C_UP && now - c->born > 8000) { conn_close(i, "连接/握手超时"); continue; }
        if (c->state != C_UP) continue;
        if (c->guest && !c->initiator && wall_ms() / 1000 - PASSSKEW >= c->gp.until) { conn_close(i, "访客通行证到期"); continue; }
        if (c->closing == 3 && now - c->born > 5000) conn_finish(i);    /* 报到链路等不到测试请求: 发完就断 */
        if (c->closing) { if (now - c->born > (c->probe_in ? 3000 : 20000)) conn_close(i, "报到完成"); continue; }
        if (now - c->last_rx > 9000) { conn_close(i, "9 秒没有回音"); continue; }
        if (now - c->last_tx > 3000) conn_send(i, F_PING, 0, NULL, 0);
    }
    for (int t = 0; t < G.nt; t++) {
        target_t *tg = &G.t[t];
        if (tg->addr6[0] && tg->conn6 < 0 && now >= tg->next6 && conn_by_peer_fam(tg->ed, 6) < 0) dial(t, 1);   /* IPv6 那条: 和 IPv4 同时挂(热备) */
        if (tg->conn >= 0 || now < tg->next_try) continue;
        if (conn_by_peer_fam(tg->ed, 4) >= 0) continue; /* 对方已经挂过来了 */
        if (!tg->addr[0] && !tg->alt[0] && !tg->nep) continue;   /* 只有 IPv6 地址 */
        dial(t, 0);
    }
    disc_tick();
    disc_pend_tick();
    qual_tick();
    if (!G.relay_off && G.lfd < 0 && now - G.lretry_ms > 30000) { G.lretry_ms = now; relay_sync(); }
    for (int q = 0; q < MAXQ; q++) if (G.q[q].fd > 0 && now - G.q[q].born > 5000) { p_close(G.q[q].fd); G.q[q].fd = 0; }
}

/* 监听(design-v3 §0 第 14 条): 每个节点都开(conf relay off 除外), 当不算可达由回连测试决定(qual.c)
 * 默认 0.0.0.0:8444, conf 的 listen 可覆盖; Linux 上开监听时顺手放行防火墙 INPUT(宿主机常有别家的 DROP) */
const char *relay_addr6(void) { return G.r6 ? G.pub6 : ""; }

const char *relay_addr(void)
{
    return G.announce[0] ? G.announce : G.pub_addr[0] ? G.pub_addr : "-";
}

void relay_sync(void)
{
    char want[80] = "", host[64]; int port = 0;
    member_t *me = member_by_ed(G.id.ed);
    if (G.relay_off) ;
    else if (G.listen[0]) snprintf(want, sizeof want, "%s", G.listen);
    else {                                             /* 名单里带地址的老写法按它的端口, 并记进 <目录>/lport: 名单去掉地址后照旧 */
        char lp[300], pt[16] = ""; snprintf(lp, sizeof lp, "%s/lport", G.dir);
        if (me && me->relay && !hostport(me->addr, host, sizeof host, &port)) {
            snprintf(pt, sizeof pt, "%d\n", port);
            char old[16] = ""; long on = m_read(lp, old, sizeof old - 1); if (on > 0) old[on] = 0;
            if (port != 8444 && strcmp(old, pt)) m_write(lp, pt, strlen(pt));
        } else { long on = m_read(lp, pt, sizeof pt - 1); port = on > 0 ? (pt[on] = 0, atoi(pt)) : 0; }
        snprintf(want, sizeof want, "0.0.0.0:%d", port > 0 && port < 65536 ? port : 8444);
    }
    if (G.lfd >= 0 && strcmp(want, G.lspec)) {
        p_close(G.lfd); G.lfd = -1;
        logf_("停止监听 %s", G.lspec); G.lspec[0] = 0;
    }
    char w6[80] = "", v6[64];                           /* 监听所有 IPv4 地址时也监听所有 IPv6(本机有 IPv6 才开得起来) */
    if (G.relay_off) ;
    else if (G.listen6[0]) snprintf(w6, sizeof w6, "%s", G.listen6);
    else if (!hostport(want, host, sizeof host, &port) && !strcmp(host, "0.0.0.0") && !local_ip6(v6, sizeof v6)) snprintf(w6, sizeof w6, "[::]:%d", port);
    if (G.lfd6 >= 0 && strcmp(w6, G.lspec6)) { p_close(G.lfd6); G.lfd6 = -1; logf_("停止监听 %s", G.lspec6); G.lspec6[0] = 0; }
    if (w6[0] && G.lfd6 < 0 && (G.lfd6 = listen_on(w6)) >= 0) { snprintf(G.lspec6, sizeof G.lspec6, "%s", w6); logf_("监听 %s", w6); }
    if (!want[0] || G.lfd >= 0) return;
    G.lfd = listen_on(want);
    if (G.lfd < 0) { logf_("监听 %s 失败, 稍后再试", want); return; }
    snprintf(G.lspec, sizeof G.lspec, "%s", want);
    logf_("监听 %s(回连测试通过、过了观察期才算可达)", want);
    if (!hostport(want, host, sizeof host, &port)) p_open_firewall(port);
}

/* 替 from 那条链路上的节点测端口: 拨 addr, 期望对方的静态公钥是 x; 结果在握手完成 / 失败时回给 from */
int probe_dial(const char *addr, const uint8_t x[32], int from)
{
    char host[64], why[96]; int port;
    if (hostport(addr, host, sizeof host, &port)) return -1;
    int fd = p_dial(host, port, 1, why, sizeof why);
    if (fd < 0) { char m[140]; snprintf(m, sizeof m, "no %s", why); conn_send(from, F_PROBEA, 0, m, strlen(m)); return -1; }
    int i = conn_alloc(fd, 1);
    if (i < 0) { p_close(fd); return -1; }
    conn_t *c = &G.c[i];
    c->state = C_CONNECTING; c->probe_for = from + 1; c->fam = addr_fam(addr);
    snprintf(c->addr, sizeof c->addr, "%s", addr);
    hs_init(&c->hs, 1, G.id.xsec, G.id.x, x);
    return 0;
}

int mesh_run(const char *dir)
{
    p_init();
    if (mesh_conf_load(dir)) return 1;
    G.lfd = G.cfd = G.lfd6 = -1;
    relay_sync();
    if (G.ctl[0]) {
        /* 控制口独占: 拿不到 = 本机已经有一份在跑。升级接班的那份要等上一份让出来(还等不到就清掉残留的旧进程);
         * 别的情况(服务管理器又拉起一份)直接退出, 退出码 0: 不算失败, 不会被反复拉起 */
        int succ = rel_successor();
        for (int k = 0; k < (succ ? 80 : 4) && (G.cfd = listen_on(G.ctl)) < 0; k++) {
            if (succ && k == 40) { logf_("控制口 %s 还被占着: 清掉残留的旧进程", G.ctl); p_kill_strays(); }
            p_sleep_ms(250);
        }
        if (G.cfd < 0 && !succ) { logf_("本机已经有一份在跑(控制口 %s 占着), 这份退出", G.ctl); exit(0); }
        if (G.cfd < 0) { logf_("控制口 %s 起不来", G.ctl); return 1; }
        uint8_t r[16]; rnd(r, 16);                      /* 控制口令牌: 每次启动换一个 */
        for (int i = 0; i < 16; i++) snprintf(G.ctl_token + 2 * i, 3, "%02x", r[i]);
        char tp[300]; snprintf(tp, sizeof tp, "%s/ctl.token", G.dir);
        if (m_write(tp, G.ctl_token, 32)) { logf_("写不了控制口令牌 %s", tp); return 1; }
        p_group_share(tp, 0);                            /* custhub 组的账号能读(没有组 / 不是 root 时什么都不做) */
    }
    targets_sync();
    rel_start();
    static pfd_t p[MAXC + MAXS + MAXQ + 2 * 16 + 8 + 8];
    static int map[MAXC + MAXS + MAXQ + 2 * 16 + 8 + 8];
    for (;;) {
        int n = 0;
        if (G.lfd >= 0) { p[n].fd = G.lfd; p[n].ev = P_IN; map[n++] = -1; }
        if (G.lfd6 >= 0) { p[n].fd = G.lfd6; p[n].ev = P_IN; map[n++] = -3; }
        if (G.cfd >= 0) { p[n].fd = G.cfd; p[n].ev = P_IN; map[n++] = -2; }
        for (int i = 0; i < MAXC; i++) if (G.c[i].state != C_FREE) {
            p[n].fd = G.c[i].fd;
            p[n].ev = (short)(P_IN | (G.c[i].out.len || G.c[i].state == C_CONNECTING ? P_OUT : 0));
            map[n++] = i;
        }
        for (int q = 0; q < MAXQ; q++) if (G.q[q].fd > 0) { p[n].fd = G.q[q].fd; p[n].ev = P_IN; map[n++] = 1000 + q; }
        hop_poll_add(p, &n, map);
        sh_poll_add(p, &n, map);
        rel_poll_add(p, &n, map);
        pkg_poll_add(p, &n, map);
        int r = p_poll(p, n, 300);
        if (r < 0) { logf_("poll: %s", p_strerr(p_lasterr())); return 1; }
        for (int k = 0; r > 0 && k < n; k++) {
            short rev = p[k].rev;
            if (!rev) continue;
            int m = map[k];
            if (m == -1) do_accept(G.lfd);
            else if (m == -3) do_accept(G.lfd6);
            else if (m == -2) ctl_accept();
            else if (m < 1000) {
                if (G.c[m].state == C_FREE || G.c[m].fd != (int)p[k].fd) continue;
                if (rev & (P_IN | P_HUP)) conn_read(m);
                if (G.c[m].state != C_FREE && (rev & P_OUT)) conn_write(m);
            }
            else if (m < 2000) ctl_io(m - 1000);
            else if (m < 3000) hop_io(m - 2000, rev);
            else if (m < 4000) sh_io(m - 3000, rev);
            else if (m < 5000) rel_io(m - 4000, rev);
            else pkg_io(m - 5000, rev);
        }
        for (int i = 0; i < MAXC; i++) if (G.c[i].state != C_FREE && G.c[i].state != C_CONNECTING && G.c[i].out.len) conn_write(i);
        tick();
        sh_tick();
        rel_tick();
    }
}
