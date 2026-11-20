/* 打洞(TCP 同时打开): 两台都连不进来、又不在同一局域网时, 让它们直接连上(失败就照旧经可达节点中转)
 *   STUN: 本机固定一个打洞端口(监听端口 + 10), 从它连可达节点的 /whoami, 对方回它看到的 "IP:端口" = 这个端口在公网上的映射;
 *         问两个不同的可达节点, 映射一样(NAT 映射不随目的地变)才把它当打洞端点写进位置记录(|p=); 不一样 = 对称型 NAT, 不报
 *   DISCO: 打洞端点随位置记录在网里传开, 不另发消息
 *   同时拨: 双方都报了打洞端点、都不可达、还没有直连时, 在同一个时间窗(每 15 秒里的前 6 秒, 按各自的钟)里每秒从打洞端口拨对方的打洞端点;
 *           两边的 SYN 交错时 NAT 都已开了口, 合成一条 TCP(同时打开); 公钥小的一方当 Noise 发起方 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct { int fd, st; char buf[600]; size_t n; int64_t t0; } Q = { -1, 0, "", 0, 0 };
static char got[2][64], asked[2][64]; static int ngot, nask, sym_logged; static int64_t next_q;

static int priv(const char *h)
{
    unsigned a = 0, b = 0;
    if (sscanf(h, "%u.%u", &a, &b) != 2) return 1;
    return a == 10 || (a == 172 && b >= 16 && b < 32) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b < 128) || a == 0;
}

static void q_close(void) { if (Q.fd >= 0) p_close(Q.fd); Q.fd = -1; Q.st = 0; Q.n = 0; }

static void round_done(int64_t now)
{
    if (ngot && (ngot == 1 || !strcmp(got[0], got[1]))) {
        if (strcmp(G.punch, got[0])) { logf_("打洞端点: %s(本机端口 %d)", got[0], G.punch_port); G.mypub_ms = 0; }
        snprintf(G.punch, sizeof G.punch, "%s", got[0]); sym_logged = 0;
    } else if (ngot == 2) {
        if (G.punch[0] || !sym_logged) logf_("打洞: 两个可达节点看到的映射不一样(%s / %s), 对称型 NAT, 不报打洞端点", got[0], got[1]);
        G.punch[0] = 0; sym_logged = 1; G.mypub_ms = 0;
    }
    next_q = now + (ngot ? 300000 : 30000);
    ngot = nask = 0;
}

/* 选一个还没问过的可达节点(IPv4 地址) */
static const char *pick(void)
{
    for (int i = 0; i < G.nr; i++) {
        rec_t *r = &G.r[i];
        if (!r->relay || addr_fam(r->addr) != 4 || !strcmp(r->addr, "-") || !member_by_ed(r->ed)) continue;
        int dup = 0; for (int k = 0; k < nask; k++) if (!strcmp(asked[k], r->addr)) dup = 1;
        if (!dup) return r->addr;
    }
    return NULL;
}

static void stun_tick(int64_t now)
{
    if (Q.fd >= 0) {
        if (now - Q.t0 > 4000) { q_close(); if (nask >= 2 || !pick()) round_done(now); return; }
        pfd_t q = { Q.fd, Q.st == 1 ? P_OUT : P_IN, 0 };
        if (p_poll(&q, 1, 0) <= 0) return;
        if (Q.st == 1) {
            if (p_dial_result(Q.fd)) { q_close(); return; }
            char rq[160]; int n = snprintf(rq, sizeof rq, "GET /whoami HTTP/1.0\r\nHost: %s\r\n\r\n", asked[nask - 1]);
            if (p_send(Q.fd, rq, (size_t)n) != n) { q_close(); return; }
            Q.st = 2; return;
        }
        long r = p_recv(Q.fd, Q.buf + Q.n, sizeof Q.buf - 1 - Q.n);
        if (r == P_AGAIN) return;
        if (r > 0) { Q.n += (size_t)r; if (Q.n < sizeof Q.buf - 1) return; }
        Q.buf[Q.n] = 0;
        const char *b = strstr(Q.buf, "\r\n\r\n"); char a[64] = "", h[64]; int port;
        if (b && !strncmp(Q.buf, "HTTP/1.0 200", 12) && sscanf(b + 4, "%63s", a) == 1 && !hostport(a, h, sizeof h, &port) && !priv(h)) snprintf(got[ngot++], sizeof got[0], "%s", a);
        q_close();
        if (nask >= 2 || !pick()) round_done(now);
        return;
    }
    if (now < next_q && !nask) return;
    const char *ad = pick(); char h[64], why[96]; int port;
    if (!ad || nask >= 2) { if (nask || ngot) round_done(now); else next_q = now + 5000; return; }   /* 还不知道哪台可达: 5 秒后再看 */
    snprintf(asked[nask++], sizeof asked[0], "%s", ad);
    if (hostport(ad, h, sizeof h, &port) || (Q.fd = p_dial_from(h, port, G.punch_port, why, sizeof why)) < 0) { Q.fd = -1; return; }
    Q.st = 1; Q.n = 0; Q.t0 = now;
}

void punch_tick(void)
{
    int64_t now = now_ms();
    char h[64]; int lp = 0;
    const char *e = getenv("CUSTHUB_PUNCH_PORT");
    G.punch_port = G.lfd >= 0 && !G.relay_off && !hostport(G.lspec, h, sizeof h, &lp) ? (e ? atoi(e) : lp + 10) : 0;
    if (!G.punch_port || G.r4 || !member_by_ed(G.id.ed)) { if (G.punch[0]) { G.punch[0] = 0; G.mypub_ms = 0; } q_close(); return; }   /* 可达的不用打洞 */
    stun_tick(now);
    if (!G.punch[0] || (wall_ms() / 1000) % 15 >= 6) return;        /* 双方共用的时间窗 */
    static int64_t last; if (now - last < 1000) return; last = now;
    for (int i = 0; i < G.nr; i++) {
        rec_t *r = &G.r[i]; int port;
        if (!r->punch[0] || r->relay || !member_by_ed(r->ed) || !memcmp(r->ed, G.id.ed, 32)) continue;   /* 对方可达的照常拨, 不用打洞 */
        if (conn_by_peer_fam(r->ed, 4) >= 0 || hostport(r->punch, h, sizeof h, &port) || priv(h)) continue;
        int busy = 0; for (int k = 0; k < MAXC; k++) if (G.c[k].state != C_FREE && G.c[k].punch && !memcmp(G.c[k].peer, r->ed, 32)) busy = 1;
        if (busy) continue;
        char why[96]; int fd = p_dial_from(h, port, G.punch_port, why, sizeof why);
        if (fd >= 0) link_punch(fd, r->ed, r->punch);
    }
}

int punch_conn_ready(int i)
{
    conn_t *c = &G.c[i];
    if (!c->punch || c->initiator) return 0;            /* 发起方照常发握手第一条 */
    c->state = C_HS;
    hs_init(&c->hs, 0, G.id.xsec, G.id.x, NULL);
    return 1;
}
