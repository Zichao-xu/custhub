/* UDP 链路(design-v3: TCP 是底座, UDP 打洞作加速): 两台之间没有直接的 TCP 链路时, 经 UDP 打洞直连
 *   一个 UDP socket(和 TCP 监听同一个端口号)收发所有 UDP 包, 按第一个字节分:
 *     'W'          查映射(STUN): 回 'w' + 对方在本机看来的 "IP:端口"
 *     'w' 地址      查映射的回答(punch.c)
 *     'P' 公钥      打洞招呼: 让本机 NAT 开口子(内容不用验, 真身份由 Noise 握手确认)
 *     'K' KCP 段    可靠传输: 一个会话(conv)= 一条链路; 链路上跑的就是 TCP 链路那套 Noise 握手 + 帧, 只是字节流换成 KCP
 *   KCP: vendor/ikcp.c(MIT), 流模式、快速重传, MTU 1200(不分片) */
#include "mesh.h"
#include "vendor/ikcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXU MAXC
#define UMTU 1200
static struct { int used, conn; ikcpcb *k; char addr[64]; uint32_t conv; } U[MAXU];
static char ubind[16];

static int loss_drop(void)                               /* 测试用: CUSTHUB_UDP_LOSS=百分比, 发出去的包按比例丢 */
{
    static int pct = -1;
    if (pct < 0) { const char *e = getenv("CUSTHUB_UDP_LOSS"); pct = e ? atoi(e) : 0; }
    return pct > 0 && rand() % 100 < pct;
}

void udp_raw(const char *addr, const void *b, size_t n)
{
    char h[64]; int port;
    if (G.ufd < 0 || hostport(addr, h, sizeof h, &port) || loss_drop()) return;
    p_udp_sendto(G.ufd, h, port, b, n);
}

static int k_out(const char *buf, int len, ikcpcb *k, void *user)
{
    (void)k;
    int s = (int)(intptr_t)user;
    static char d[UMTU + 8];
    if (len > UMTU) return -1;
    d[0] = 'K'; memcpy(d + 1, buf, (size_t)len);
    udp_raw(U[s].addr, d, (size_t)len + 1);
    return 0;
}

static int u_new(uint32_t conv, const char *addr)
{
    for (int s = 0; s < MAXU; s++) if (!U[s].used) {
        ikcpcb *k = ikcp_create(conv, (void *)(intptr_t)s);
        if (!k) return -1;
        ikcp_setoutput(k, k_out);
        ikcp_setmtu(k, UMTU);
        ikcp_wndsize(k, 512, 512);
        ikcp_nodelay(k, 1, 20, 2, 1);                    /* 快速模式: 20ms 节拍(热备链路常驻, 不要太勤)、2 次重复 ACK 就重传、不做拥塞退让 */
        k->stream = 1;
        memset(&U[s], 0, sizeof U[s]);
        U[s].used = 1; U[s].k = k; U[s].conv = conv; U[s].conn = -1;
        snprintf(U[s].addr, sizeof U[s].addr, "%s", addr);
        return s;
    }
    return -1;
}

void udp_free(int s)
{
    if (s < 0 || s >= MAXU || !U[s].used) return;
    ikcp_release(U[s].k);
    memset(&U[s], 0, sizeof U[s]);
}

int udp_active(void) { for (int s = 0; s < MAXU; s++) if (U[s].used) return 1; return 0; }

/* 开 / 关 UDP socket: 跟着 TCP 监听走, 同一个端口号 */
void udp_sync(void)
{
    char h[64], want[16] = ""; int port = 0;
    if (!G.relay_off && G.lfd >= 0 && !hostport(G.lspec, h, sizeof h, &port)) snprintf(want, sizeof want, "%d", port);
    if (G.ufd >= 0 && strcmp(want, ubind)) { p_close(G.ufd); G.ufd = -1; ubind[0] = 0; }
    if (!want[0] || G.ufd >= 0) return;
    G.ufd = p_udp_bind(port);
    if (G.ufd < 0) { logf_("UDP 端口 %d 开不了, 不用 UDP", port); return; }
    snprintf(ubind, sizeof ubind, "%s", want);
    logf_("UDP 监听 0.0.0.0:%d", port);
}

/* 本机发起: 到对方打洞端点开一条 UDP 链路(公钥小的一方当 Noise 发起方) */
int udp_dial(const uint8_t ed[32], const char *addr)
{
    member_t *pm = member_by_ed(ed);
    if (!pm || G.ufd < 0) return -1;
    uint8_t r[4]; rnd(r, 4);
    uint32_t conv = (uint32_t)r[0] | (uint32_t)r[1] << 8 | (uint32_t)r[2] << 16 | (uint32_t)r[3] << 24;
    int s = u_new(conv ? conv : 1, addr);
    if (s < 0) return -1;
    int i = conn_new_udp(s + 1, 1, ed, addr);
    if (i < 0) { udp_free(s); return -1; }
    U[s].conn = i;
    return i;
}

/* 链路要发的字节 → KCP(留着背压: KCP 里待发的太多就先不收) */
void udp_send_conn(int i)
{
    conn_t *c = &G.c[i];
    int s = c->udp - 1;
    if (s < 0 || !U[s].used) return;
    while (c->out.len && ikcp_waitsnd(U[s].k) < 1024) {
        size_t n = c->out.len < 65536 ? c->out.len : 65536;
        if (ikcp_send(U[s].k, (const char *)c->out.p, (int)n) < 0) break;
        buf_eat(&c->out, n);
    }
}

static void drain(int s)
{
    static char b[MAXMSG + 1024];
    int n;
    while (U[s].used && (n = ikcp_peeksize(U[s].k)) > 0) {
        if (n > (int)sizeof b) { conn_close(U[s].conn, "UDP 包太大"); return; }
        if (ikcp_recv(U[s].k, b, n) != n) return;
        int i = U[s].conn;
        if (i < 0 || G.c[i].state == C_FREE || G.c[i].udp != s + 1) return;
        conn_feed(i, (const uint8_t *)b, (size_t)n);
    }
}

void udp_io(void)
{
    static char b[2048]; char from[64];
    for (int k = 0; k < 256; k++) {
        long n = p_udp_recvfrom(G.ufd, b, sizeof b - 1, from, sizeof from);
        if (n == P_AGAIN || n < 0) return;
        if (n < 1) continue;
        if (b[0] == 'W') { char r[80]; int rn = snprintf(r, sizeof r, "w%s", from); udp_raw(from, r, (size_t)rn); continue; }
        if (b[0] == 'w') { b[n] = 0; punch_udp_reply(from, b + 1); continue; }
        if (b[0] == 'P') continue;                       /* 打洞招呼: 收到就说明口子开了, KCP 会自己重传 */
        if (b[0] != 'K' || n < 25) continue;
        const uint8_t *p = (const uint8_t *)b + 1;
        uint32_t conv = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
        int s = -1;
        for (int j = 0; j < MAXU; j++) if (U[j].used && U[j].conv == conv && !strcmp(U[j].addr, from)) { s = j; break; }
        if (s < 0) {                                     /* 新会话: 对方先拨过来, 本机当 Noise 应答方 */
            if (G.relay_off) continue;
            s = u_new(conv, from);
            if (s < 0) continue;
            int i = conn_new_udp(s + 1, 0, NULL, from);
            if (i < 0) { udp_free(s); continue; }
            U[s].conn = i;
        }
        ikcp_input(U[s].k, (const char *)p, n - 1);
        drain(s);
    }
}

void udp_tick(void)
{
    uint32_t now = (uint32_t)now_ms();
    for (int s = 0; s < MAXU; s++) if (U[s].used) {
        int i = U[s].conn;
        if (i < 0 || G.c[i].state == C_FREE || G.c[i].udp != s + 1) { udp_free(s); continue; }
        if (G.c[i].out.len) udp_send_conn(i);
        ikcp_update(U[s].k, now);
    }
}
