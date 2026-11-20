/* 可达自检(design-v3 §0 第 14 条): 可达节点是功能, 节点自检有资质就开、没有就关, 名单不管
 *   资质 = 有别的节点从外面回连本机报出的地址成功(Noise 握手证明连到的就是本机), 并且过了观察期
 *   观察期: 回连一直通、在线一段时间(默认 30 分钟; 上次就可达的免观察, 见地址簿)才在位置记录里声明"我是可达节点"
 *   复查: 默认每 10 分钟请一个连着的成员回连一次; 不通就撤掉声明、停止转发, 1 分钟后再试
 *   请别人测: F_PROBE(内容 = 本机监听端口, 或 conf announce 的整个地址); 对方用它看到的本机 IP 拼地址去拨, 回 F_PROBEA "ok 地址" / "no 原因"
 *   报到中的节点(还没批准)也能请可达节点测, 跑接入命令的人当场看到端口结果; 不算可达的报到节点发 "-", 可达节点就不等了 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int64_t env_s(const char *k, long def)
{
    const char *e = getenv(k);
    long v = e ? atol(e) : 0;
    return (v > 0 ? v : def) * (int64_t)1000;
}

/* 免观察: 上次就是可达的(地址簿里有本机, 一测不通就删) / 名单里带地址的老写法 */
static int seeded(void)
{
    member_t *me = member_by_ed(G.id.ed);
    return me && (hint_addr(G.id.ed) || (me->relay && me->addr[0]));
}

int me_seed(void) { return seeded(); }

/* 观察期进度存 <目录>/obs(已观察的毫秒数): 观察期中重启(比如升级)接着算, 不从头来; 一测不通或已算可达就删 */
static int64_t obs_wrote;
static int64_t obs_saved(void)
{
    char p[300], t[32]; snprintf(p, sizeof p, "%s/obs", G.dir);
    long n = m_read(p, t, sizeof t - 1);
    if (n <= 0) return 0;
    t[n] = 0; long long v = atoll(t);
    return v > 0 ? (int64_t)v : 0;
}
static void obs_save(int64_t ms)
{
    char p[300], t[32]; snprintf(p, sizeof p, "%s/obs", G.dir);
    if (ms <= 0) { remove(p); return; }
    int n = snprintf(t, sizeof t, "%lld\n", (long long)ms);
    m_write(p, t, (size_t)n);
}

static void port_state(const char *fmt, const char *a, const char *b)   /* 端口检测结果, 有变化才写日志 */
{
    char t[sizeof G.port_state];
    snprintf(t, sizeof t, fmt, a, b);
    if (strcmp(t, G.port_state)) logf_("端口: %s", t);
    snprintf(G.port_state, sizeof G.port_state, "%s", t);
}

static void set_relay(int on, const char *why)
{
    if (!on) hint_note(G.id.ed, NULL);                 /* 不可达了: 下次启动要重新过观察期 */
    else if (strcmp(relay_addr(), "-")) hint_note(G.id.ed, relay_addr());
    if (on == G.me_relay) return;
    G.me_relay = on;
    if (on) logf_("可达: 对外地址 %s(%s)", relay_addr(), why);
    else logf_("不可达: %s", why);
    G.mypub_ms = 0;                                    /* 位置记录马上重发 */
}

void qual_tick(void)
{
    int64_t now = now_ms();
    if (G.relay_off) { snprintf(G.port_state, sizeof G.port_state, "本机设了 relay off(不对外)"); set_relay(0, "本机设了 relay off"); return; }
    if (G.lfd < 0) { port_state("没在监听%s%s", "", ""); set_relay(0, "没在监听"); return; }
    if (G.probing && now > G.probe_deadline) {
        G.probing = 0; G.ok_since = 0; obs_save(0); G.probe_next = now + env_s("CUSTHUB_MESH_PROBE_RETRY_S", 60);
        port_state("不通: 测试没回音%s%s", "", "");
        set_relay(0, "回连测试没回音");
    }
    if (G.ok_since && !G.me_relay && (seeded() || now - G.ok_since >= env_s("CUSTHUB_MESH_OBS_S", 1800))) {
        set_relay(1, seeded() ? "上次就可达, 免观察" : "过了观察期");
        obs_save(0);
    }
    if (G.ok_since && !G.me_relay && now - obs_wrote >= 5000) { obs_wrote = now; obs_save(now - G.ok_since); }
    upnp_tick();                                       /* 路由器自动映射 / 续租(到点才真做) */
    if (G.probing || now < G.probe_next) return;
    int best = -1;                                     /* 找一个连着的成员替本机测, 可达节点优先 */
    for (int i = 0; i < MAXC; i++) {
        conn_t *c = &G.c[i];
        if (c->state != C_UP || c->closing || c->probe_for || c->probe_in || c->guest) continue;
        if (best < 0 || (c->peer_relay && !G.c[best].peer_relay)) best = i;
    }
    if (best < 0) return;
    char pl[80]; int port = 0; char host[64];
    if (G.announce[0]) snprintf(pl, sizeof pl, "%s", G.announce);
    else if (!hostport(G.lspec, host, sizeof host, &port)) snprintf(pl, sizeof pl, "%d", G.upnp_port ? G.upnp_port : port);
    else return;
    conn_send(best, F_PROBE, 0, pl, strlen(pl));
    G.probing = 1; G.probe_conn = best; G.probe_deadline = now + 15000;
}

void qual_probe_ans(int from, const uint8_t *pl, size_t n)
{
    (void)from;
    if (!G.probing || n >= 150) return;
    char t[160]; memcpy(t, pl, n); t[n] = 0;
    int64_t now = now_ms();
    G.probing = 0;
    if (!strncmp(t, "ok ", 3)) {
        if (!G.ok_since) {
            int64_t had = G.me_relay ? 0 : obs_saved();  /* 观察期中重启过: 接着算 */
            G.ok_since = now - had;
            if (had) logf_("观察期接着算: 已观察 %lld 秒", (long long)(had / 1000));
        }
        if (!G.announce[0]) snprintf(G.pub_addr, sizeof G.pub_addr, "%s", t + 3);
        if (G.me_relay) hint_note(G.id.ed, relay_addr());   /* 地址变了跟着记 */
        G.probe_next = now + env_s("CUSTHUB_MESH_PROBE_S", 600);
        port_state(G.upnp_port ? "已开启(UPnP 自动映射): %s 从外面连得进来%s" : "已开启: %s 从外面连得进来%s",
                   relay_addr(), G.me_relay ? ", 可达" : seeded() ? "" : ", 观察期中");
    } else {
        G.ok_since = 0; obs_save(0);
        G.probe_next = now + env_s("CUSTHUB_MESH_PROBE_RETRY_S", 60);
        char hint[200] = "", host[64], ip[48] = ""; int port = 0;
        if (!hostport(G.lspec, host, sizeof host, &port)) {   /* 告诉跑命令的人怎么手动开(可选) */
            if (upnp_lan_ip()[0]) snprintf(ip, sizeof ip, "%s", upnp_lan_ip()); else if (p_local_ip("8.8.8.8", ip, sizeof ip)) snprintf(ip, sizeof ip, "本机");
            snprintf(hint, sizeof hint, "; 想让这台机器帮忙转发, 请在路由器上把 TCP %d 映射到 %s:%d(可选, 不开也能接入)", port, ip, port);
        }
        port_state("不通: %s%s", t[0] == 'n' && t[1] == 'o' && t[2] == ' ' ? t + 3 : t, hint);
        set_relay(0, "回连测试不通");
    }
}

void qual_probe_in(int from, const uint8_t *pl, size_t n)
{
    if (n == 0 || n >= 70) return;
    char t[80], addr[80], host[64]; int port;
    memcpy(t, pl, n); t[n] = 0;
    if (!strcmp(t, "-")) { if (G.c[from].closing == 3) conn_finish(from); return; }   /* 对方不算可达, 不用测 */
    int k = 0;
    for (int i = 0; i < MAXC; i++) if (G.c[i].state != C_FREE && G.c[i].probe_for) k++;
    if (k >= 8) { const char *m = "no 测试方太忙"; conn_send(from, F_PROBEA, 0, m, strlen(m)); return; }
    if (strchr(t, ':')) snprintf(addr, sizeof addr, "%s", t);   /* 对方指定了整个地址(announce) */
    else {                                                     /* 用本机看到的对方 IP + 它的监听端口 */
        if (hostport(G.c[from].addr, host, sizeof host, &port)) return;
        int p = atoi(t);
        if (p <= 0 || p > 65535) return;
        snprintf(addr, sizeof addr, "%s:%d", host, p);
    }
    probe_dial(addr, G.c[from].hs.rs, from);
}
