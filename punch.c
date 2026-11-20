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

/* ---------- UDP: 查映射(发 'W' 给两台可达节点的同一个 IP:端口, 回 'w' 地址)、打洞(没有直接的 TCP 链路时) ---------- */
static char ua[8][64], ug[8][64]; static int nua, nug, usym; static int64_t udl, next_uq;   /* 一次问所有可达节点(有的 UDP 不通) */

void punch_udp_reply(const char *from, const char *addr)
{
    char h[64]; int port;
    if (!udl || hostport(addr, h, sizeof h, &port) || priv(h) || nug >= 8) return;
    for (int k = 0; k < nua; k++) if (!strcmp(ua[k], from)) { snprintf(ug[nug++], sizeof ug[0], "%s", addr); ua[k][0] = 0; return; }
}

static void ustun_tick(int64_t now)
{
    if (G.ufd < 0) { G.upunch[0] = 0; return; }
    if (udl) {
        if (now < udl && nug < nua) return;
        udl = 0;
        int same = 1; for (int k = 1; k < nug; k++) if (strcmp(ug[k], ug[0])) same = 0;
        if (nug && same) {
            if (strcmp(G.upunch, ug[0])) { logf_("UDP 打洞端点: %s", ug[0]); G.mypub_ms = 0; }
            snprintf(G.upunch, sizeof G.upunch, "%s", ug[0]); usym = 0;
        } else if (nug >= 2) {
            if (G.upunch[0] || !usym) logf_("UDP 打洞: 两个可达节点看到的映射不一样(%s / %s), 对称型 NAT, 不报", ug[0], ug[1]);
            G.upunch[0] = 0; usym = 1; G.mypub_ms = 0;
        }
        next_uq = now + (nug ? 300000 : 30000);
        return;
    }
    if (now < next_uq) return;
    nua = nug = 0;
    char me[64] = "", mh[64]; int mp;                    /* 本机公网 IP: 同一个 IP 后面的(同一个 NAT)问了也是回环, 看到的不准, 不问 */
    if (!hostport(G.pub_addr, mh, sizeof mh, &mp) || !hostport(G.upunch, mh, sizeof mh, &mp) || !hostport(G.punch, mh, sizeof mh, &mp)) snprintf(me, sizeof me, "%s", mh);
    for (int i = 0; i < G.nr && nua < 8; i++) {
        rec_t *r = &G.r[i]; char rh[64]; int rp;
        if (!r->relay || addr_fam(r->addr) != 4 || !strcmp(r->addr, "-") || !member_by_ed(r->ed)) continue;
        if (me[0] && strncmp(me, "127.", 4) && !hostport(r->addr, rh, sizeof rh, &rp) && !strcmp(rh, me)) continue;   /* 回环(本机测试)不算 */
        snprintf(ua[nua++], sizeof ua[0], "%s", r->addr);
    }
    if (!nua) { next_uq = now + 5000; return; }
    for (int k = 0; k < nua; k++) udp_raw(ua[k], "W", 1);
    udl = now + 3000;
}

/* UDP 热备: 和每个在线成员都挂一条 UDP(平时流量走 TCP, TCP 断了马上走 UDP)
 *   对方的 UDP 地址: 局域网端点 / 可达地址(和 TCP 同一个端口号) / UDP 打洞端点, 轮流试; 双方都可以拨, 重复的按公钥规则留一条
 *   都在打洞时间窗里拨(打洞要双方同时); 拨不通的退避, 最长 5 分钟 */
static struct { uint8_t ed[32]; int64_t next, back; int rr; } UB[MAXM]; static int nub;

static void udp_links(int64_t now)
{
    static char mine[16][48]; static int nmine; static int64_t mine_at;
    if (!mine_at || now - mine_at > 30000) { mine_at = now; nmine = p_local_ipv4s(mine, 16); }
    char lh[64]; int lp = 0; hostport(G.lspec, lh, sizeof lh, &lp);
    for (int i = 0; i < G.nr; i++) {
        rec_t *r = &G.r[i]; char h[64]; int port;
        if (!member_by_ed(r->ed) || !memcmp(r->ed, G.id.ed, 32) || now - r->rx_ms > 120000) continue;
        int b = 0; while (b < nub && memcmp(UB[b].ed, r->ed, 32)) b++;
        if (b == nub) { if (nub >= MAXM) continue; memset(&UB[nub], 0, sizeof UB[0]); memcpy(UB[nub].ed, r->ed, 32); UB[nub].back = 15000; nub++; }
        if (conn_by_peer_fam(r->ed, 'u') >= 0) { UB[b].back = 15000; UB[b].next = 0; continue; }
        int busy = 0; for (int k = 0; k < MAXC; k++) if (G.c[k].state != C_FREE && G.c[k].udp && !memcmp(G.c[k].peer, r->ed, 32)) busy = 1;
        if (busy || now < UB[b].next) continue;
        const char *cand[8]; int nc = 0;
        char eb[200]; snprintf(eb, sizeof eb, "%s", r->eps); char *sv = NULL;
        static char eps[4][64]; int ne = 0;
        for (char *e = m_tok(eb, ",", &sv); e && ne < 4; e = m_tok(NULL, ",", &sv)) {
            if (hostport(e, h, sizeof h, &port)) continue;
            int own = 0; for (int k = 0; k < nmine; k++) if (!strcmp(mine[k], h) && port == lp) own = 1;
            if (!own) { snprintf(eps[ne], sizeof eps[0], "%s", e); cand[nc++] = eps[ne++]; }
        }
        if (r->upunch[0] && !hostport(r->upunch, h, sizeof h, &port) && !priv(h)) cand[nc++] = r->upunch;   /* 量出来的 UDP 映射先试 */
        if (r->relay && addr_fam(r->addr) == 4 && strcmp(r->addr, "-") && strcmp(r->addr, r->upunch)) cand[nc++] = r->addr;
        if (!nc) continue;
        const char *a = cand[UB[b].rr++ % nc];
        uint8_t m[33]; m[0] = 'P'; memcpy(m + 1, G.id.ed, 32);
        udp_raw(a, m, sizeof m);                         /* 招呼: 给本机 NAT 开口子 */
        udp_dial(r->ed, a);                              /* 握手包本身也在打洞, KCP 会重传; 双方都拨时重复的那条按公钥规则去掉 */
        UB[b].next = now + UB[b].back; UB[b].back = UB[b].back < 300000 ? UB[b].back * 2 : 300000;
    }
}

void punch_tick(void)
{
    int64_t now = now_ms();
    char h[64]; int lp = 0;
    const char *e = getenv("CUSTHUB_PUNCH_PORT");
    G.punch_port = G.lfd >= 0 && !G.relay_off && !hostport(G.lspec, h, sizeof h, &lp) ? (e ? atoi(e) : lp + 10) : 0;
    if (!member_by_ed(G.id.ed)) return;
    int punching = G.punch_port && !G.r4;                /* TCP: 可达的不用查映射、不用打洞 */
    if (!punching) { if (G.punch[0]) { G.punch[0] = 0; G.mypub_ms = 0; } q_close(); }
    else stun_tick(now);
    ustun_tick(now);                                     /* UDP: 每台都查、都报(可达的 UDP 端口未必和 TCP 一样, 比如路由器自己占着) */
    if ((wall_ms() / 1000) % 15 >= 6) return;            /* 双方共用的时间窗 */
    static int64_t last; if (now - last < 1000) return; last = now;
    if (G.ufd >= 0 && !getenv("CUSTHUB_NO_UDP")) udp_links(now);
    if (!punching || !G.punch[0] || getenv("CUSTHUB_NO_TCP_PUNCH")) return;
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
