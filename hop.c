/* 流: 可达节点转发(S_FWD 成对) + 本机两端(S_INIT 发起 / S_RESP 接收)
 *   OPEN  内容 = 目标公钥 32 + 来源公钥 32 + 剩余跳数 1; 可达节点按 route() 往下转, 流号逐段翻译
 *   流里先跑一次端到端 Noise IK(第一条 DATA 带要开的服务, 加密), 之后 DATA 都是端到端密文: 可达节点只看得到谁连谁
 *   连通层不管权限: 接收端把"谁、要开什么"交给服务层(svc.c), 由它和通行证层决定接不接
 *   额度: 每个方向 WIN 字节在途; 收端写给本地后回 CREDIT。可达节点不管额度, 只原样转 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROUTE_ERR "路由:"

static int s_find(int conn, uint32_t sid)
{
    for (int i = 0; i < MAXS; i++) if (G.s[i].kind != S_FREE && G.s[i].conn == conn && G.s[i].sid == sid) return i;
    return -1;
}

static int s_alloc(int kind)
{
    for (int i = 0; i < MAXS; i++) if (G.s[i].kind == S_FREE) {
        memset(&G.s[i], 0, sizeof G.s[i]);
        G.s[i].kind = kind; G.s[i].fd = -1; G.s[i].pair = -1; G.s[i].conn = -1; G.s[i].credit = WIN;
        return i;
    }
    return -1;
}

static void s_free(int si)
{
    stream_t *s = &G.s[si];
    if (s->fd >= 0) p_close(s->fd);
    buf_free(&s->lout);
    memset(s, 0, sizeof *s);
}

static void st_close(int si, const char *why)   /* 告诉对端并释放 */
{
    stream_t *s = &G.s[si];
    if (s->conn >= 0 && G.c[s->conn].state == C_UP) conn_send(s->conn, F_CLOSE, s->sid, why, strlen(why));
    s_free(si);
}

static int avoided(int c, const int *avoid, int na)
{
    for (int k = 0; k < na; k++) if (avoid[k] == c) return 1;
    return 0;
}

/* 选下一跳: 直连对方 > 对方位置记录里挂着的可达节点(且我和它连着) > (我不是可达节点时)任一可达节点 */
int route(const uint8_t dst[32], const int *avoid, int na)
{
    int k = conn_by_peer(dst);
    if (k >= 0 && !avoided(k, avoid, na)) return k;
    rec_t *r = rec_by_ed(dst);
    if (r && strcmp(r->relays, "-")) {
        char tmp[160], *sv = NULL; snprintf(tmp, sizeof tmp, "%s", r->relays);
        for (char *t = m_tok(tmp, ",", &sv); t; t = m_tok(NULL, ",", &sv)) {
            member_t *m = member_by_name(t);
            if (!m || !ed_relay(m->ed)) continue;
            int c = conn_by_peer(m->ed);
            if (c >= 0 && !avoided(c, avoid, na)) return c;
        }
    }
    if (!G.me_relay)
        for (int t = 0; t < G.nt; t++) {
            int c = conn_by_peer(G.t[t].ed);
            if (c >= 0 && !avoided(c, avoid, na)) return c;
        }
    return -1;
}

static void send_open(int conn, uint32_t sid, const uint8_t dst[32], const uint8_t src[32], int ttl)
{
    uint8_t o[65];
    memcpy(o, dst, 32); memcpy(o + 32, src, 32); o[64] = (uint8_t)ttl;
    conn_send(conn, F_OPEN, sid, o, sizeof o);
}

/* ---------- 发起端 ---------- */
static void init_fail(int si, const char *why)
{
    stream_t *s = &G.s[si];
    char m[200]; int n = snprintf(m, sizeof m, "ERR %s\n", why);
    if (s->fd >= 0 && p_send(s->fd, m, (size_t)n) < 0) { /* 客户端已走 */ }
    logf_("连接 %s %s 失败: %s", name_of(s->dst), s->req, why);
    s_free(si);
}

static void init_try(int si)
{
    stream_t *s = &G.s[si];
    member_t *m = member_by_ed(s->dst);
    if (!m) { init_fail(si, "名单里没有这个节点"); return; }
    if (s->ntried >= 8) { init_fail(si, "试过的路都不通"); return; }
    int r = route(s->dst, s->tried, s->ntried);
    if (r < 0) { init_fail(si, "找不到路(没有连得上的可达节点)"); return; }
    s->tried[s->ntried++] = r;
    s->conn = r; s->sid = conn_new_sid(r);
    hs_init(&s->hs, 1, G.id.xsec, G.id.x, m->x);
    static uint8_t m1[PASSMAX + 256]; static char pl[PASSMAX + 32];
    int pn = snprintf(pl, sizeof pl, "%s\n", s->req);              /* 请求一行 + 本机通行证(没有就空, 对方会拒) */
    pn += pass_load(s->dst, s->req, pl + pn, sizeof pl - (size_t)pn);
    long n = hs_write1(&s->hs, (const uint8_t *)pl, (size_t)pn, m1);
    send_open(r, s->sid, s->dst, G.id.ed, 3);
    conn_send(r, F_DATA, s->sid, m1, (size_t)n);
}

int hop_open_local(int fd, const uint8_t dst[32], const char *req)
{
    int si = s_alloc(S_INIT);
    if (si < 0) return -1;
    G.s[si].fd = fd; snprintf(G.s[si].req, sizeof G.s[si].req, "%s", req); memcpy(G.s[si].dst, dst, 32);
    init_try(si);
    return 0;
}

/* ---------- 接收端 ---------- */
static void resp_first(int si, const uint8_t *pl, size_t n)
{
    stream_t *s = &G.s[si];
    static uint8_t txt[PASSMAX + 32]; uint8_t m2[128];
    long r = hs_read1(&s->hs, pl, n, txt, sizeof txt - 1);
    if (r < 0) { st_close(si, "端到端握手失败"); return; }
    txt[r] = 0;
    char *nl = strchr((char *)txt, '\n'), why[64];
    if (!nl) { st_close(si, "请求格式不对"); return; }
    *nl = 0;
    s->fd = svc_open(s->hs.rs, (const char *)txt, nl + 1, (size_t)(r - (nl + 1 - (char *)txt)), s->dst, why, sizeof why);
    snprintf(s->req, sizeof s->req, "%s", (const char *)txt);
    if (s->fd < 0) { st_close(si, why); return; }
    long w = hs_write2(&s->hs, NULL, 0, m2, &s->tx, &s->rx);
    conn_send(s->conn, F_DATA, s->sid, m2, (size_t)w);
    s->up = 1;
    logf_("%s 凭通行证开本机 %s(经 %s)", name_of(s->dst), s->req, name_of(G.c[s->conn].peer));
}

/* ---------- 端点收帧 ---------- */
static void ep_finish_check(int si)
{
    stream_t *s = &G.s[si];
    if (s->lfin && s->rfin && !s->lout.len) st_close(si, "完成");
}

static void ep_frame(int si, int type, const uint8_t *pl, size_t n)
{
    stream_t *s = &G.s[si];
    static uint8_t pt[MAXMSG];
    switch (type) {
    case F_DATA:
        if (!s->up && s->kind == S_RESP) { resp_first(si, pl, n); return; }
        if (!s->up) {
            if (hs_read2(&s->hs, pl, n, pt, sizeof pt, &s->tx, &s->rx) < 0) {
                conn_send(s->conn, F_CLOSE, s->sid, "端到端握手失败", strlen("端到端握手失败"));
                init_fail(si, "对方身份不对"); return;
            }
            s->up = 1;
            if (p_send(s->fd, "OK\n", 3) != 3) { st_close(si, "本地客户端已走"); return; }
            logf_("已连上 %s %s(经 %s)", name_of(s->dst), s->req, name_of(G.c[s->conn].peer));
            return;
        }
        {
            long r = cs_open(&s->rx, pl, n, pt);
            if (r < 0) { st_close(si, "解密失败"); return; }
            if (buf_add(&s->lout, pt, (size_t)r)) st_close(si, "内存不足");
        }
        return;
    case F_FIN:
        s->rfin = 1;
        if (!s->lout.len && s->fd >= 0) p_shut_wr(s->fd);
        ep_finish_check(si);
        return;
    case F_CREDIT:
        if (n == 4) s->credit += (long)((uint32_t)pl[0] << 24 | (uint32_t)pl[1] << 16 | (uint32_t)pl[2] << 8 | pl[3]);
        return;
    case F_CLOSE: {
        char why[128]; size_t k = n < sizeof why - 1 ? n : sizeof why - 1;
        memcpy(why, pl, k); why[k] = 0;
        if (s->kind == S_INIT && !s->up) {
            if (!strncmp(why, ROUTE_ERR, strlen(ROUTE_ERR))) { logf_("这条路不通(%s), 换一条", why); init_try(si); }
            else init_fail(si, why);
            return;
        }
        /* 对端已关: 不再往链路发任何东西; 已收到的先写给本地再收尾(同一批里 DATA、FIN、CLOSE 常常一起到) */
        s->conn = -1; s->lfin = s->rfin = 1;
        if (s->up && s->lout.len && s->fd >= 0) return;
        s_free(si);
        return;
    }
    }
}

void hop_frame(int i, int type, uint32_t sid, const uint8_t *pl, size_t n)
{
    if (type == F_OPEN) {
        if (n != 65 || s_find(i, sid) >= 0) return;
        const uint8_t *dst = pl, *src = pl + 32; int ttl = pl[64];
        if (!memcmp(dst, G.id.ed, 32)) {
            int si = s_alloc(S_RESP);
            if (si < 0) { conn_send(i, F_CLOSE, sid, "满了", 6); return; }
            G.s[si].conn = i; G.s[si].sid = sid;
            hs_init(&G.s[si].hs, 0, G.id.xsec, G.id.x, NULL);
            return;
        }
        char why[160];
        if (G.c[i].guest && !G.c[i].initiator) {          /* 访客只能开往通行证 to 里的机器, 来源必须是它自己 */
            char pw[80];
            if (memcmp(src, G.c[i].peer, 32) || pass_allows(&G.c[i].gp, G.c[i].peer, dst, NULL, wall_ms() / 1000, pw, sizeof pw)) {
                snprintf(why, sizeof why, "不转发: %s", memcmp(src, G.c[i].peer, 32) ? "来源不是访客自己" : pw);
                conn_send(i, F_CLOSE, sid, why, strlen(why));
                return;
            }
        }
        int avoid[1] = { i };
        int r = (!G.me_relay || ttl == 0) ? -1 : route(dst, avoid, 1);
        if (r < 0) {
            snprintf(why, sizeof why, ROUTE_ERR " %s 到不了 %s", G.name, name_of(dst));
            conn_send(i, F_CLOSE, sid, why, strlen(why));
            return;
        }
        int a = s_alloc(S_FWD), b = a >= 0 ? s_alloc(S_FWD) : -1;
        if (b < 0) { if (a >= 0) s_free(a); conn_send(i, F_CLOSE, sid, ROUTE_ERR " 满了", strlen(ROUTE_ERR " 满了")); return; }
        G.s[a].conn = i; G.s[a].sid = sid; G.s[a].pair = b;
        G.s[b].conn = r; G.s[b].sid = conn_new_sid(r); G.s[b].pair = a;
        send_open(r, G.s[b].sid, dst, src, ttl - 1);
        logf_("转发 %s → %s(%s → %s)", name_of(src), name_of(dst), name_of(G.c[i].peer), name_of(G.c[r].peer));
        return;
    }
    int si = s_find(i, sid);
    if (si < 0) return;
    stream_t *s = &G.s[si];
    if (s->kind != S_FWD) { ep_frame(si, type, pl, n); return; }
    stream_t *p = &G.s[s->pair];
    if (type == F_DATA && G.dump) {
        char path[300]; snprintf(path, sizeof path, "%s/dump", G.dir);
        FILE *f = fopen(path, "ab"); if (f) { fwrite(pl, 1, n, f); fclose(f); }
    }
    conn_send(p->conn, type, p->sid, pl, n);
    if (type == F_CLOSE) { int pi = s->pair; s_free(si); s_free(pi); }
}

void hop_conn_down(int i)
{
    for (int si = 0; si < MAXS; si++) {
        stream_t *s = &G.s[si];
        if (s->kind == S_FREE || s->conn != i) continue;
        if (s->kind == S_FWD) {
            int pi = s->pair;
            if (pi >= 0 && G.c[G.s[pi].conn].state == C_UP)
                conn_send(G.s[pi].conn, F_CLOSE, G.s[pi].sid, ROUTE_ERR " 转发链路断了", strlen(ROUTE_ERR " 转发链路断了"));
            s_free(si); if (pi >= 0) s_free(pi);
        } else if (s->kind == S_INIT && !s->up) init_try(si);
        else s_free(si);
    }
}

/* ---------- 本地连接收发 ---------- */
static int can_read(stream_t *s)
{
    return s->up && !s->lfin && s->credit > 0 && s->conn >= 0 && G.c[s->conn].out.len < OUTMAX;
}

void hop_poll_add(pfd_t *p, int *np, int *map)
{
    for (int si = 0; si < MAXS; si++) {
        stream_t *s = &G.s[si];
        if ((s->kind != S_INIT && s->kind != S_RESP) || s->fd < 0 || !s->up) continue;
        short ev = (short)((s->lout.len ? P_OUT : 0) | (can_read(s) ? P_IN : 0));
        if (!ev) continue;
        p[*np].fd = s->fd; p[*np].ev = ev; map[(*np)++] = 2000 + si;
    }
}

static void send_credit(stream_t *s)
{
    if (s->conn < 0) return;
    uint8_t c[4] = { (uint8_t)(s->unacked >> 24), (uint8_t)(s->unacked >> 16), (uint8_t)(s->unacked >> 8), (uint8_t)s->unacked };
    conn_send(s->conn, F_CREDIT, s->sid, c, 4);
    s->unacked = 0;
}

void hop_io(int si, short rev)
{
    stream_t *s = &G.s[si];
    if (s->kind == S_FREE) return;
    if ((rev & P_OUT) && s->lout.len) {
        long w = p_send(s->fd, s->lout.p, s->lout.len);
        if (w == P_FAIL) { st_close(si, "本地写失败"); return; }
        if (w > 0) {
            buf_eat(&s->lout, (size_t)w); s->unacked += w;
            if (s->unacked >= 32 * 1024 || !s->lout.len) send_credit(s);
            if (s->rfin && !s->lout.len) p_shut_wr(s->fd);
        }
    }
    if ((rev & (P_IN | P_HUP)) && can_read(s)) {
        static uint8_t b[CHUNK], ct[CHUNK + 16];
        size_t want = s->credit < CHUNK ? (size_t)s->credit : CHUNK;
        long r = p_recv(s->fd, b, want);
        if (r == 0) { s->lfin = 1; conn_send(s->conn, F_FIN, s->sid, NULL, 0); }
        else if (r == P_FAIL) { st_close(si, "本地读失败"); return; }
        else if (r == P_AGAIN) { }
        else {
            long n = cs_seal(&s->tx, b, (size_t)r, ct);
            conn_send(s->conn, F_DATA, s->sid, ct, (size_t)n);
            s->credit -= r;
        }
    }
    if (G.s[si].kind != S_FREE) ep_finish_check(si);
}
