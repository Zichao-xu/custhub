/* 事件(custhub watch / wait): 守护每 2 秒对比一次各成员的状态, 变了就记一条, 最近 512 条放在内存里
 *   类型: online / offline / version / capability / link(本机到它: direct ↔ relay ↔ none)
 *         offline_long(离线满 10 分钟, 只记一次) / behind(版本落后网里最新的满 30 分钟, 只记一次) —— 这两种是该告诉人的
 *   控制口: EVENTS <从哪个编号之后> [json]   CHECK <名字> <条件> [值]
 *   告警(custhub watch --notify): 只对 offline_long / behind / capability 变差 发系统通知 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXE 512
typedef struct { long id; int64_t wall; char name[32], type[16], from[40], to[40]; } ev_t;
static ev_t E[MAXE]; static long next_id = 1;
static void add_s(buf_t *o, const char *s) { buf_add(o, s, strlen(s)); }
static struct { uint8_t ed[32]; int seen, online, linkk; char ver[16], cap[12]; int64_t off_since, behind_since; int off_told, behind_told; } S[MAXM];

static void push(const char *name, const char *type, const char *from, const char *to)
{
    ev_t *e = &E[next_id % MAXE];
    e->id = next_id++; e->wall = wall_ms();
    snprintf(e->name, sizeof e->name, "%s", name); snprintf(e->type, sizeof e->type, "%s", type);
    snprintf(e->from, sizeof e->from, "%s", from); snprintf(e->to, sizeof e->to, "%s", to);
    logf_("事件: %s %s %s → %s", name, type, from[0] ? from : "-", to[0] ? to : "-");
}

static const char *cap_now(const uint8_t ed[32], rec_t *r)
{
    int v4 = r && r->relay && addr_fam(r->addr) == 4, v6 = r && r->addr6[0] == '[', pu = r && (r->punch[0] || r->upunch[0]);
    (void)ed; return v4 && v6 ? "dualstack" : v4 ? "public" : v6 ? "ipv6" : pu ? "p2p" : "relay";
}

static int online_now(const uint8_t ed[32], rec_t *r)    /* 有直连, 或 150 秒内收到过它的记录(测试可用 CUSTHUB_ONLINE_S 改) */
{
    static int64_t lim; if (!lim) lim = (int64_t)(getenv("CUSTHUB_ONLINE_S") ? atoi(getenv("CUSTHUB_ONLINE_S")) : 150) * 1000;
    return conn_by_peer(ed) >= 0 || (r && now_ms() - r->rx_ms < lim);
}

static int link_now(const uint8_t ed[32]) { if (conn_by_peer(ed) >= 0) return 2; return route(ed, NULL, 0) >= 0 ? 1 : 0; }
static const char *link_name(int k) { return k == 2 ? "direct" : k == 1 ? "relay" : "none"; }

void events_tick(void)
{
    static int64_t at;
    int64_t now = now_ms();
    if (now - at < 2000) return;
    at = now;
    const char *newest = CH_VERSION;                    /* 网里见过的最新版本 */
    for (int i = 0; i < G.nr; i++) if (member_by_ed(G.r[i].ed) && G.r[i].ver[0] && ver_cmp(G.r[i].ver, newest) > 0) newest = G.r[i].ver;
    for (int t = 0; t < G.trust.n; t++) {
        member_t *m = &G.trust.m[t];
        if (!memcmp(m->ed, G.id.ed, 32)) continue;
        int k = 0; while (k < MAXM && S[k].seen && memcmp(S[k].ed, m->ed, 32)) k++;
        if (k >= MAXM) continue;
        rec_t *r = rec_by_ed(m->ed);
        int on = online_now(m->ed, r), lk = on ? link_now(m->ed) : 0;
        const char *cap = on ? cap_now(m->ed, r) : "";
        const char *ver = r ? r->ver : "";
        if (!S[k].seen) {                                 /* 第一次: 只记下, 不算变化 */
            memcpy(S[k].ed, m->ed, 32); S[k].seen = 1; S[k].online = on; S[k].linkk = lk;
            snprintf(S[k].ver, sizeof S[k].ver, "%s", ver); snprintf(S[k].cap, sizeof S[k].cap, "%s", cap);
            S[k].off_since = on ? 0 : now; continue;
        }
        if (on != S[k].online) { push(m->name, on ? "online" : "offline", "", ""); S[k].online = on; S[k].off_since = on ? 0 : now; S[k].off_told = 0; }
        if (!on && S[k].off_since && !S[k].off_told && now - S[k].off_since >= (int64_t)(getenv("CUSTHUB_EV_OFFLINE_S") ? atoi(getenv("CUSTHUB_EV_OFFLINE_S")) : 600) * 1000) {
            push(m->name, "offline_long", "", ""); S[k].off_told = 1;
        }
        if (ver[0] && strcmp(ver, S[k].ver)) { push(m->name, "version", S[k].ver, ver); snprintf(S[k].ver, sizeof S[k].ver, "%s", ver); S[k].behind_since = 0; S[k].behind_told = 0; }
        if (on && cap[0] && strcmp(cap, S[k].cap)) { push(m->name, "capability", S[k].cap, cap); snprintf(S[k].cap, sizeof S[k].cap, "%s", cap); }
        if (on && lk != S[k].linkk) { push(m->name, "link", link_name(S[k].linkk), link_name(lk)); S[k].linkk = lk; }
        if (on && ver[0] && ver_cmp(ver, newest) < 0) {   /* 落后: 在线却一直没升上来 */
            if (!S[k].behind_since) S[k].behind_since = now;
            else if (!S[k].behind_told && now - S[k].behind_since >= (int64_t)(getenv("CUSTHUB_EV_BEHIND_S") ? atoi(getenv("CUSTHUB_EV_BEHIND_S")) : 1800) * 1000) { push(m->name, "behind", ver, newest); S[k].behind_told = 1; }
        } else S[k].behind_since = 0;
    }
}

void events_text(buf_t *o, long since, int json)
{
    long lo = next_id - MAXE > since + 1 ? next_id - MAXE : since + 1;
    if (json) add_s(o, "[");
    int first = 1;
    for (long id = lo; id < next_id; id++) {
        ev_t *e = &E[id % MAXE];
        if (e->id != id) continue;
        char h[200];
        if (json) {
            snprintf(h, sizeof h, "%s{\"id\":%ld,\"time\":%lld,\"name\":", first ? "" : ",", e->id, (long long)(e->wall / 1000)); add_s(o, h); json_str(o, e->name);
            add_s(o, ",\"type\":"); json_str(o, e->type); add_s(o, ",\"from\":"); json_str(o, e->from); add_s(o, ",\"to\":"); json_str(o, e->to); add_s(o, "}");
        } else { snprintf(h, sizeof h, "%ld %lld %s %s %s %s\n", e->id, (long long)(e->wall / 1000), e->name, e->type, e->from[0] ? e->from : "-", e->to[0] ? e->to : "-"); add_s(o, h); }
        first = 0;
    }
    if (json) add_s(o, "]\n");
}

long events_last(void) { return next_id - 1; }

/* CHECK <名字> <条件> [值]: online / offline / version <v>(版本 >= v) / reachable(能被连进来) / direct(本机到它有直连) → "yes" / "no" */
int events_check(const char *name, const char *cond, const char *val, char *out, size_t cap)
{
    member_t *m = member_by_name(name);
    if (!m) { snprintf(out, cap, "ERR 名单里没有 %s", name); return -1; }
    rec_t *r = rec_by_ed(m->ed); int on = online_now(m->ed, r), y;
    if (!strcmp(cond, "online")) y = on;
    else if (!strcmp(cond, "offline")) y = !on;
    else if (!strcmp(cond, "version")) y = on && r && val && val[0] && ver_cmp(r->ver, val) >= 0;
    else if (!strcmp(cond, "reachable")) { const char *c = on ? cap_now(m->ed, r) : ""; y = !strcmp(c, "public") || !strcmp(c, "dualstack") || !strcmp(c, "ipv6"); }
    else if (!strcmp(cond, "direct")) y = conn_by_peer(m->ed) >= 0;
    else { snprintf(out, cap, "ERR 不认识的条件 %s(有 online offline version reachable direct)", cond); return -1; }
    snprintf(out, cap, "%s", y ? "yes" : "no");
    return 0;
}

/* ---------- 命令行 ---------- */
static int ask(const char *dir, const char *line, char *out, size_t cap)
{
    int fd = ctl_open_raw(dir);
    if (fd < 0) return -1;
    size_t n = strlen(line);
    if (p_send(fd, line, n) != (long)n || p_send(fd, "\n", 1) != 1) { p_close(fd); return -1; }
    size_t k = 0; long r;
    while (k < cap - 1 && (r = p_recv(fd, out + k, cap - 1 - k)) > 0) k += (size_t)r;
    p_close(fd); out[k] = 0;
    return 0;
}

static const char *zh(const char *type)
{
    return !strcmp(type, "online") ? "上线" : !strcmp(type, "offline") ? "离线" : !strcmp(type, "offline_long") ? "离线超过 10 分钟" :
           !strcmp(type, "version") ? "版本" : !strcmp(type, "capability") ? "能力" : !strcmp(type, "link") ? "本机到它" : !strcmp(type, "behind") ? "版本落后超过 30 分钟" : type;
}

/* custhub alerts on|off|status: 当前用户登录时自动在后台跑 watch --notify(这台电脑上谁开谁收) */
int cmd_alerts(const char *dir, const char *what)
{
    char why[300];
    if (!strcmp(what, "status")) { printf("告警: %s\n", p_autostart_on("alerts") ? "开着(登录时自动在后台看, 离线满 10 分钟、版本落后满 30 分钟、能力变差时弹通知)" : "关着"); return 0; }
    int on = !strcmp(what, "on");
    if (!on && strcmp(what, "off")) { fprintf(stderr, "用法: custhub alerts on | off | status\n"); return 2; }
    if (on) { char b[64]; if (ask(dir, "EVENTS -1", b, sizeof b)) { fprintf(stderr, "连不上本机守护(custhub 服务没在跑?)\n"); return 1; } }
    char args[1400]; snprintf(args, sizeof args, "watch %s --notify", dir);   /* 带上节点目录(不是默认目录时也找得到守护) */
    if (strchr(dir, ' ')) { fprintf(stderr, "节点目录里有空格, 自启动写不了: %s\n", dir); return 1; }
    if (p_autostart("alerts", on, args, why, sizeof why)) { fprintf(stderr, "%s\n", why); return 1; }
    printf(on ? "告警已开: 现在起、以及以后每次登录, 后台看着; 离线满 10 分钟、版本落后满 30 分钟、能力变差时弹通知\n" : "告警已关\n");
    return 0;
}

/* custhub watch [--json] [--notify]: 持续打印事件(只要新的); --notify 对该告诉人的(离线太久、版本卡住、能力变差)弹桌面通知 */
int cmd_watch(const char *dir, int json, int notify)
{
    if (notify && !json) p_hide_console();              /* 登录时后台跑的那份: Windows 上别留个黑窗口 */
    static char b[256 * 1024];
    while (ask(dir, "EVENTS -1", b, sizeof b)) {         /* 后台跑的(--notify): 守护可能比它晚起来, 等着; 前台看的直接报错 */
        if (!notify) { fprintf(stderr, "连不上本机守护\n"); return 1; }
        p_sleep_ms(10000);
    }
    long last = atol(b);
    for (;;) {
        char l[60]; snprintf(l, sizeof l, "EVENTS %ld", last);
        if (ask(dir, l, b, sizeof b)) {                  /* 守护重启(升级)了: 事件编号从头来 */
            if (!notify) { fprintf(stderr, "连不上本机守护\n"); return 1; }
            p_sleep_ms(10000); while (ask(dir, "EVENTS -1", b, sizeof b)) p_sleep_ms(10000); last = atol(b); continue;
        }
        if (atol(b) == 0 && last > 0 && !strchr(b, ' ')) { }   /* 空: 没有新事件 */
        char *sv = NULL;
        for (char *ln = m_tok(b, "\n", &sv); ln; ln = m_tok(NULL, "\n", &sv)) {
            long id; long long ts; char nm[32], ty[16], fr[40], to[40];
            if (sscanf(ln, "%ld %lld %31s %15s %39s %39s", &id, &ts, nm, ty, fr, to) != 6) continue;
            last = id;
            if (json) printf("{\"id\":%ld,\"time\":%lld,\"name\":\"%s\",\"type\":\"%s\",\"from\":\"%s\",\"to\":\"%s\"}\n", id, ts, nm, ty, strcmp(fr, "-") ? fr : "", strcmp(to, "-") ? to : "");
            else if (strcmp(fr, "-") || strcmp(to, "-")) printf("%s %s: %s → %s\n", nm, zh(ty), fr, to);
            else printf("%s %s\n", nm, zh(ty));
            fflush(stdout);
            int worse = !strcmp(ty, "capability") && (!strcmp(to, "relay") || (!strcmp(to, "p2p") && strcmp(fr, "relay")));
            if (notify && (!strcmp(ty, "offline_long") || !strcmp(ty, "behind") || worse)) {
                char t[80], m[200]; snprintf(t, sizeof t, "custhub: %s", nm);
                if (!strcmp(ty, "behind")) snprintf(m, sizeof m, "版本卡在 %s, 网里已经是 %s 了", fr, to);
                else if (worse) snprintf(m, sizeof m, "能力变差: %s → %s", fr, to);
                else snprintf(m, sizeof m, "离线超过 10 分钟");
                p_notify(t, m);
            }
        }
        p_sleep_ms(1000);
    }
}

/* custhub wait <名字> <online|offline|reachable|direct|version V> [--timeout 秒]: 条件成立返回 0, 超时返回 4 */
int cmd_wait(const char *dir, const char *name, const char *cond, const char *val, int tmo)
{
    char l[200], b[300]; snprintf(l, sizeof l, "CHECK %s %s %s", name, cond, val ? val : "");
    int64_t end = now_ms() + (int64_t)(tmo > 0 ? tmo : 600) * 1000;
    for (;;) {
        if (ask(dir, l, b, sizeof b)) { fprintf(stderr, "连不上本机守护\n"); return 1; }
        if (!strncmp(b, "ERR", 3)) { fprintf(stderr, "%s", b + 4); return 2; }
        if (!strncmp(b, "yes", 3)) return 0;
        if (now_ms() > end) { fprintf(stderr, "等到超时: %s 还不满足 %s%s%s\n", name, cond, val ? " " : "", val ? val : ""); return 4; }
        p_sleep_ms(1000);
    }
}
