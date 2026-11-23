/* 控制口(只听 127.0.0.1): 应用层从这里用网络
 *   CONNECT <名字|公钥> <端口|sh>\n → OK\n 之后就是一条通到对方服务(本机端口 / shell)的字节流; 失败 ERR 原因\n
 *   LS\n                          → 本机视角的网络状态
 *   TRUST\n                       → 当前成员名单原文
 *   TRUSTPUT <base64>\n           → 交一份新名单(验签、版本更新才收, 收了就沿链路传遍全网)
 *   PENDQ <base64>\n              → 主钥匙当场签的查询("custhub-mesh-pending <秒>\n"+签名), 转给连着的可达节点, 汇总它们的待批准
 * 每条连接第一行必须是 AUTH <令牌>(守护每次启动随机生成, 写在 <目录>/ctl.token; 读得到它的才是本机 root / 管理员 / 本人)
 * mesh connect 是给 ssh ProxyCommand 用的小客户端: 标准输入输出 ↔ 控制口
 * 控制口暂不鉴权(对方的服务层 + 通行证层把关); 正式版要加本机令牌 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static void add(buf_t *o, const char *fmt, ...);

void ctl_accept(void)
{
    int fd = p_accept(G.cfd, NULL, 0);
    if (fd < 0) return;
    for (int q = 0; q < MAXQ; q++) if (G.q[q].fd <= 0) {
        memset(&G.q[q], 0, sizeof G.q[q]);
        G.q[q].fd = fd; G.q[q].born = now_ms();
        return;
    }
    p_close(fd);
}

static void put_all(int fd, const void *pv, size_t n)
{
    const char *p = pv;
    p_block(fd);
    while (n) { long w = p_send(fd, p, n); if (w <= 0) break; p += w; n -= (size_t)w; }
}

static void put_str(int fd, const char *s) { put_all(fd, s, strlen(s)); }

static int resolve(const char *s, uint8_t ed[32])
{
    member_t *m = member_by_name(s);
    if (m) { memcpy(ed, m->ed, 32); return 0; }
    return b64_decode(s, strlen(s), ed, 32) == 32 && member_by_ed(ed) ? 0 : -1;
}

void ctl_io(int qi)
{
    ctlq_t *q = &G.q[qi];
    long r = p_recv(q->fd, q->line + q->n, sizeof q->line - 1 - q->n);
    if (r == P_AGAIN) return;
    if (r <= 0) { p_close(q->fd); q->fd = 0; return; }
    q->n += (size_t)r; q->line[q->n] = 0;
    char *nl = strchr(q->line, '\n');
    if (!nl) { if (q->n >= sizeof q->line - 1) { p_close(q->fd); q->fd = 0; } return; }
    if (!q->authed) {                                   /* 第一行: 令牌(常数时间比较) */
        *nl = 0;
        int bad = strncmp(q->line, "AUTH ", 5) || strlen(q->line + 5) != 32 || !G.ctl_token[0];
        unsigned diff = 0;
        for (int i = 0; !bad && i < 32; i++) diff |= (unsigned)(q->line[5 + i] ^ G.ctl_token[i]);
        if (bad || diff) { put_str(q->fd, "ERR 令牌不对\n"); p_close(q->fd); q->fd = 0; return; }
        q->authed = 1;
        size_t rest = q->n - (size_t)(nl + 1 - q->line);
        memmove(q->line, nl + 1, rest); q->n = rest; q->line[q->n] = 0;
        nl = strchr(q->line, '\n');
        if (!nl) return;                                /* 命令还没到 */
    }
    *nl = 0;
    int fd = q->fd; q->fd = 0;
    char cmd[16], a[64], b[160];
    int f = sscanf(q->line, "%15s %63s %159s", cmd, a, b);
    if (f >= 1 && !strcmp(cmd, "TRUST")) { put_all(fd, G.trust.text, G.trust.tlen); p_close(fd); return; }
    if (f >= 2 && (!strcmp(cmd, "TRUSTPUT") || !strcmp(cmd, "PENDQ"))) {
        static uint8_t d[MAXTEXT];
        const char *arg = q->line + strlen(cmd) + 1;
        long dn = b64_decode(arg, strlen(arg), d, sizeof d - 1);
        if (dn <= 0) { put_str(fd, "ERR base64 不对\n"); p_close(fd); return; }
        d[dn] = 0;
        if (!strcmp(cmd, "TRUSTPUT")) {
            long old = G.trust.ver;
            int r = mtrust_apply((const char *)d, (size_t)dn, "本机控制口");
            char m[120];
            snprintf(m, sizeof m, r > 0 ? "OK 名单 v%ld → v%ld, 正沿链路传开\n" : r == 0 ? "OK 已有 v%ld, 不比它新(v%ld)\n" : "ERR 验签不过或格式不对(现有 v%ld)\n%.0ld",
                     old, G.trust.ver);
            put_str(fd, m); p_close(fd); return;
        }
        if (G.pq_fd > 0) { put_str(fd, "ERR 上一个查询还没完\n"); p_close(fd); return; }
        int n = 0;
        uint8_t asked[MAXC][32]; int na = 0;                /* 问每个直连的成员(每台问一次): 报到可能落在任何一台 */
        for (int i = 0; i < MAXC; i++) {
            if (G.c[i].state != C_UP || G.c[i].closing || !G.c[i].pm || G.c[i].guest) continue;
            int dup = 0; for (int k = 0; k < na; k++) if (!memcmp(asked[k], G.c[i].peer, 32)) dup = 1;
            if (dup) continue;
            memcpy(asked[na++], G.c[i].peer, 32); conn_send(i, F_PENDQ, 0, d, (size_t)dn); n++;
        }
        if (!n) { put_str(fd, "ERR 没有连着的成员\n"); p_close(fd); return; }
        G.pq_fd = fd; G.pq_wait = n; G.pq_deadline = now_ms() + 4000; G.pq_out.len = 0;
        return;
    }
    if (f >= 1 && !strcmp(cmd, "QUIT")) {                /* custhub remove 用: 正常退出(退出码 0, 服务管理器不当失败重启) */
        put_str(fd, "OK 退出\n"); p_close(fd);
        logf_("收到 QUIT, 退出");
        exit(0);
    }
    if (f >= 2 && !strcmp(cmd, "PING")) {               /* custhub ping <名字> */
        uint8_t ed[32]; buf_t o = { 0 };
        if (resolve(a, ed)) { put_str(fd, "ERR 名单里没有这个节点\n"); p_close(fd); return; }
        if (f >= 3 && !strcmp(b, "json")) ping_json(&o, ed); else ping_text(&o, ed);
        put_all(fd, o.p, o.len); buf_free(&o); p_close(fd); return;
    }
    if (f >= 2 && !strcmp(cmd, "TARGETS")) {             /* 目标表达式 → 名字列表(custhub exec 用) */
        char out[2048]; put_str(fd, targets_resolve(q->line + 8, out, sizeof out) ? out : out); put_str(fd, "\n"); p_close(fd); return;
    }
    if (f >= 1 && !strcmp(cmd, "EVENTS")) {              /* EVENTS <从哪个编号之后(-1 = 只要编号)> [json] */
        buf_t o = { 0 }; long since = f >= 2 ? atol(a) : 0;
        if (since < 0) { char l[40]; snprintf(l, sizeof l, "%ld\n", events_last()); put_str(fd, l); p_close(fd); return; }
        events_text(&o, since, f >= 3 && !strcmp(b, "json")); put_all(fd, o.p, o.len); buf_free(&o); p_close(fd); return;
    }
    if (f >= 3 && !strcmp(cmd, "CHECK")) {               /* CHECK <名字> <条件> [值] */
        char c3[64] = "", v[64] = "", out[200]; sscanf(q->line, "%*s %*s %63s %63s", c3, v);
        events_check(a, c3, v, out, sizeof out); put_str(fd, out); put_str(fd, "\n"); p_close(fd); return;
    }
    if (f >= 1 && !strcmp(cmd, "LOG")) {                 /* custhub log(本机): LOG <行数> [关键字(空格写成 %20)] */
        buf_t o = { 0 }; char key[160] = ""; size_t kl = 0;
        for (const char *c = f >= 3 ? b : ""; *c && kl < sizeof key - 1; c++) { if (c[0] == '%' && c[1] == '2' && (c[2] == '0' || c[2] == '5')) { key[kl++] = c[2] == '0' ? ' ' : '%'; c += 2; } else key[kl++] = *c; }
        key[kl] = 0; log_tail(&o, f >= 2 ? atoi(a) : 100, key); put_all(fd, o.p, o.len); buf_free(&o); p_close(fd); return;
    }
    if (f >= 1 && !strcmp(cmd, "INV")) { buf_t o = { 0 }; inventory_text(&o, f >= 2 && !strcmp(a, "json")); put_all(fd, o.p, o.len); buf_free(&o); p_close(fd); return; }
    if (f >= 1 && !strcmp(cmd, "NETCHECK")) { buf_t o = { 0 }; if (f >= 2 && !strcmp(a, "json")) netcheck_json(&o); else netcheck_text(&o); put_all(fd, o.p, o.len); buf_free(&o); p_close(fd); return; }
    if (f >= 1 && !strcmp(cmd, "LINE")) {               /* 新机器的一行接入命令: 地址取网里一台可达、版本最新的机器(rel.c 的只读 HTTP) */
        char l[700]; join_line(l, sizeof l); put_str(fd, l); p_close(fd); return;
    }
    if (f >= 1 && !strcmp(cmd, "CODE")) {               /* 本机接入码(组里的账号读不了钥匙, 问守护) */
        char code[8], l[16]; join_code(G.id.ed, code); snprintf(l, sizeof l, "%s\n", code);
        put_str(fd, l); p_close(fd); return;
    }
    if (f >= 1 && (!strcmp(cmd, "PASSLS") || !strcmp(cmd, "PASSPUT"))) {   /* custhub pass: 装 / 列本机通行证(存放只有 root 能写, 由守护代办) */
        buf_t o = { 0 };
        if (!strcmp(cmd, "PASSPUT")) {
            static uint8_t d[PASSMAX + 1]; char slot[300];
            const char *arg = f >= 2 ? q->line + 8 : "";
            long dn = b64_decode(arg, strlen(arg), d, sizeof d - 1);
            if (dn <= 0) { put_str(fd, "ERR base64 不对\n"); p_close(fd); return; }
            d[dn] = 0;
            if (pass_store((const char *)d, (size_t)dn, slot, sizeof slot)) { add(&o, "ERR %s\n", slot); put_all(fd, o.p, o.len); buf_free(&o); p_close(fd); return; }
            logf_("本机控制口装上一张通行证(%s)", slot);
            pass_text(&o, (const char *)d, (size_t)dn);
        } else pass_text(&o, NULL, 0);
        put_all(fd, o.p, o.len); buf_free(&o); p_close(fd); return;
    }
    if (f >= 1 && !strcmp(cmd, "LS")) {
        buf_t o = { 0 }; ls_text(&o);
        put_all(fd, o.p, o.len); buf_free(&o); p_close(fd); return;
    }
    uint8_t ed[32];
    if (f == 3 && !strcmp(cmd, "CONNECT")) {
        int port = atoi(b);
        char req[160];
        if (!strcmp(b, "sh")) snprintf(req, sizeof req, "sh");
        else if (!strncmp(b, "bench:", 6) || !strcmp(b, "file") || !strncmp(b, "info:", 5)) snprintf(req, sizeof req, "%s", b);
        else snprintf(req, sizeof req, "port:%d", port);
        if (resolve(a, ed)) { put_str(fd, "ERR 名单里没有这个节点\n"); p_close(fd); return; }
        const char *need = !strncmp(b, "bench:", 6) ? "bench" : !strcmp(b, "file") ? "file" : !strncmp(b, "info:", 5) ? "info" : NULL;
        if (need && !has_feat(ed, need)) {               /* 对方没报这个功能: 当场说清楚, 不去试 */
            rec_t *r = rec_by_ed(ed); char m[200];
            snprintf(m, sizeof m, "ERR 对方(版本 %s)还不支持 %s, 等它自动升级后再试\n", r && r->ver[0] ? r->ver : "未知", need);
            put_str(fd, m); p_close(fd); return;
        }
        if ((strcmp(b, "sh") && strcmp(b, "file") && strncmp(b, "bench:", 6) && strncmp(b, "info:", 5) && (port <= 0 || port > 65535)) || hop_open_local(fd, ed, req)) { put_str(fd, "ERR 参数不对或流满了\n"); p_close(fd); }
        return;
    }
    put_str(fd, "ERR 不认识的命令\n");
    p_close(fd);
}

static void add(buf_t *o, const char *fmt, ...)
{
    char t[1200]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(t, sizeof t, fmt, ap); va_end(ap);
    if (n > 0) buf_add(o, t, (size_t)n < sizeof t ? (size_t)n : sizeof t - 1);
}

/* 一行通用接入命令(Win7 起的 Windows: Win+R / cmd / PowerShell, 弹 UAC; Mac / Linux: 终端), 第一行是用的地址
 * 地址: 现在在线、从外面连得进来、版本最新(至少 0.3.11, 有只读 HTTP)的机器, 本机也算; 一台都没有就退回 GitHub(Win7 用不了) */
void join_line(char *out, size_t cap)
{
    const char *best = NULL, *bv = "0.3.11"; char self[80] = "";
    int64_t now = now_ms();
    for (int six = 0; six < 2 && !best; six++) {        /* IPv4 地址优先(新机器多半只有 IPv4), 都没有才用 IPv6 的 */
        const char *ma = six ? relay_addr6() : G.r4 ? relay_addr() : "";
        if (ma[0] && strcmp(ma, "-") && ver_cmp(CH_VERSION, bv) >= 0) { snprintf(self, sizeof self, "%s", ma); best = self; bv = CH_VERSION; }
        for (int i = 0; i < G.nr; i++) {
            rec_t *r = &G.r[i];
            const char *a = six ? (r->addr6[0] == '[' ? r->addr6 : "") : (r->relay && addr_fam(r->addr) == 4 ? r->addr : "");
            if (!a[0] || !strcmp(a, "-") || now - r->rx_ms > 180000 || !member_by_ed(r->ed)) continue;
            if (ver_cmp(r->ver, bv) > 0 || (!best && ver_cmp(r->ver, bv) >= 0)) { best = a; bv = r->ver; }
        }
    }
    if (best) {
        snprintf(out, cap, "http://%s\npowershell -c \"start powershell -verb runas -args '-NoExit -c iex(New-Object Net.WebClient).DownloadString(''http://%s/ps1'')'\"; curl -fsSL http://%s/sh|sh\n", best, best, best);
        return;
    }
    char u[200]; snprintf(u, sizeof u, "https://github.com/%s/releases/latest/download", G.github[0] ? G.github : "Zichao-xu/custhub");
    snprintf(out, cap, "-\npowershell -c \"start powershell -verb runas -args 'irm https://ghfast.top/%s/custhub3-join.ps1|iex;pause'\"; curl -fsSL %s/custhub3-join.sh|sh\n", u, u);
}

static const char *link_kind(const conn_t *c) { return c->udp ? "UDP" : c->fam == 6 ? "TCP IPv6" : "TCP IPv4"; }

/* ---------- custhub inventory: 所有机器的基本信息, 来自位置记录(不连任何机器) ---------- */
static void split_info(const char *mi, char f[4][100])
{
    char b[400]; snprintf(b, sizeof b, "%s", mi);
    for (char *c = b; *c; c++) if (*c == '_') *c = ' ';
    for (int k = 0; k < 4; k++) f[k][0] = 0;
    char *p = b; for (int k = 0; k < 4 && p; k++) { char *bar = k < 3 ? strchr(p, '|') : NULL; if (bar) *bar = 0; snprintf(f[k], 100, "%s", p); p = bar ? bar + 1 : NULL; }
}

static const char *cap_of(int v4, int v6, int punch, int json)
{
    if (json) return v4 && v6 ? "dualstack" : v4 ? "public" : v6 ? "ipv6" : punch ? "p2p" : "relay";
    return v4 && v6 ? "双栈" : v4 ? "公网" : v6 ? "IPv6" : punch ? "P2P" : "跳转";
}

/* 目标表达式: 逗号分开的名字或分组; 分组按机器自报的平台: @all @online @win @win7 @linux @android @mac(都不含本机)
 * 返回 0 时 out = "A-2 A-7"; 失败返回 -1, out = "ERR 原因" */
int targets_resolve(const char *expr, char *out, size_t cap)
{
    char e[1024]; snprintf(e, sizeof e, "%s", expr); out[0] = 0; size_t ol = 0; int n = 0;
    uint8_t seen[MAXM][32];
    char *sv = NULL;
    for (char *t = m_tok(e, ",", &sv); t; t = m_tok(NULL, ",", &sv)) {
        while (*t == ' ') t++;
        if (!*t) continue;
        int grp = t[0] == '@', hit = 0;
        for (int i = 0; i < G.trust.n; i++) {
            member_t *m = &G.trust.m[i];
            if (!grp && strcmp(m->name, t)) continue;
            if (grp) {
                if (!memcmp(m->ed, G.id.ed, 32)) continue;
                rec_t *r = rec_by_ed(m->ed);
                int online = conn_by_peer(m->ed) >= 0 || (r && now_ms() - r->rx_ms < 150000);
                const char *plat = r ? r->info : "";
                if (!strcmp(t, "@all")) ;
                else if (!strcmp(t, "@online")) { if (!online) continue; }
                else if (!strcmp(t, "@win")) { if (strncmp(plat, "win", 3)) continue; }
                else if (!strcmp(t, "@win7")) { if (strncmp(plat, "win7", 4)) continue; }
                else if (!strcmp(t, "@linux")) { if (strncmp(plat, "linux", 5)) continue; }
                else if (!strcmp(t, "@android")) { if (strncmp(plat, "android", 7)) continue; }
                else if (!strcmp(t, "@mac")) { if (strncmp(plat, "mac", 3)) continue; }
                else { snprintf(out, cap, "ERR 不认识的分组 %s(有 @all @online @win @win7 @linux @android @mac)", t); return -1; }
            }
            hit = 1;
            int dup = 0; for (int k = 0; k < n; k++) if (!memcmp(seen[k], m->ed, 32)) dup = 1;
            if (dup || n >= MAXM) continue;
            memcpy(seen[n++], m->ed, 32);
            ol += (size_t)snprintf(out + ol, cap - ol, "%s%s", ol ? " " : "", m->name);
        }
        if (!hit && !grp) { snprintf(out, cap, "ERR 名单里没有 %s", t); return -1; }
    }
    if (!n) { snprintf(out, cap, "ERR 没有匹配的机器"); return -1; }
    return 0;
}

/* 按屏幕宽度补空格(中文占 2 格), 超宽的截掉; w = 0 不补不截 */
static void cell(buf_t *o, const char *s, int w)
{
    int used = 0; const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        int n = *p < 0x80 ? 1 : (*p & 0xe0) == 0xc0 ? 2 : (*p & 0xf0) == 0xe0 ? 3 : 4, cw = n >= 3 ? 2 : 1;
        if (w && used + cw > w) break;
        buf_add(o, p, (size_t)n); used += cw; p += n;
    }
    if (w) { buf_add(o, "  ", 1); while (used++ < w) buf_add(o, " ", 1); }
}

void inventory_text(buf_t *o, int json)
{
    int64_t now = now_ms(); int first = 1;
    if (json) add(o, "[");
    else { cell(o, "名字", 6); cell(o, "状态", 4); cell(o, "机器名", 16); cell(o, "系统", 30); cell(o, "版本", 7); cell(o, "能力", 4); cell(o, "最近", 9); cell(o, "本机到它", 0); add(o, "\n"); }
    for (int t = 0; t < G.trust.n; t++) {
        member_t *m = &G.trust.m[t];
        int self = !memcmp(m->ed, G.id.ed, 32);
        rec_t *r = self ? NULL : rec_by_ed(m->ed);
        char f[4][100]; split_info(self ? my_info() : r ? r->info : "", f);
        const char *ver = self ? CH_VERSION : r ? r->ver : "";
        int c = self ? -1 : conn_by_peer(m->ed);
        long age = r ? (long)((now - r->rx_ms) / 1000) : -1;
        int online = self || c >= 0 || (r && age < 150);
        int v4 = self ? G.r4 : r && r->relay && addr_fam(r->addr) == 4, v6 = self ? G.r6 : r && r->addr6[0] == '[';
        int punch = self ? (G.punch[0] || G.upunch[0]) : r && (r->punch[0] || r->upunch[0]);
        const char *addr = self ? (G.r4 ? relay_addr() : "") : r && r->relay ? r->addr : "";
        char link[160] = "";
        if (c >= 0) snprintf(link, sizeof link, "%s %dms %s", G.c[c].udp ? "UDP" : G.c[c].fam == 6 ? "TCP IPv6" : "TCP IPv4", G.c[c].rtt, G.c[c].addr);
        else if (!self && online) { int k = route(m->ed, NULL, 0); if (k >= 0) snprintf(link, sizeof link, "经 %s", name_of(G.c[k].peer)); }
        if (json) {
            add(o, "%s{\"name\":", first ? "" : ","); json_str(o, m->name);
            add(o, ",\"self\":%s,\"online\":%s,\"version\":", self ? "true" : "false", online ? "true" : "false"); json_str(o, ver);
            add(o, ",\"platform\":"); json_str(o, f[0]); add(o, ",\"host\":"); json_str(o, f[1][0] ? f[1] : m->host);
            add(o, ",\"os\":"); json_str(o, f[2]); add(o, ",\"model\":"); json_str(o, f[3]);
            add(o, ",\"capability\":\"%s\",\"addr\":", cap_of(v4, v6, punch, 1)); json_str(o, addr);
            add(o, ",\"addr6\":"); json_str(o, self ? (G.r6 ? G.pub6 : "") : r && r->addr6[0] == '[' ? r->addr6 : "");
            add(o, ",\"features\":"); json_str(o, self ? FEATURES : r ? r->feats : "");
            add(o, ",\"last_seen_s\":%ld,\"link\":", self ? 0L : age);
            if (c >= 0) { add(o, "{\"kind\":\"%s\",\"addr\":", G.c[c].udp ? "udp" : G.c[c].fam == 6 ? "tcp6" : "tcp4"); json_str(o, G.c[c].addr); add(o, ",\"rtt_ms\":%d}", G.c[c].rtt); }
            else if (link[0]) { add(o, "{\"kind\":\"relay\",\"via\":"); json_str(o, link + 4); add(o, "}"); }
            else add(o, "null");
            add(o, "}"); first = 0;
        } else {
            char ag[24]; if (self) snprintf(ag, sizeof ag, "-"); else if (age < 0) snprintf(ag, sizeof ag, "从没见过"); else snprintf(ag, sizeof ag, "%lds 前", age);
            cell(o, m->name, 6); cell(o, self ? "本机" : online ? "在线" : "离线", 4); cell(o, f[1][0] ? f[1] : m->host[0] ? m->host : "-", 16);
            cell(o, f[2][0] ? f[2] : "-", 30); cell(o, ver[0] ? ver : "-", 7); cell(o, online || self ? cap_of(v4, v6, punch, 0) : "-", 4); cell(o, ag, 9);
            cell(o, self ? "本机" : link[0] ? link : "-", 0); add(o, "\n");
        }
    }
    if (json) add(o, "]\n");
}

void ping_text(buf_t *o, const uint8_t ed[32])
{
    int n = 0, best = conn_by_peer(ed);
    for (int i = 0; i < MAXC; i++) {
        conn_t *c = &G.c[i];
        if (c->state != C_UP || memcmp(c->peer, ed, 32)) continue;
        char r[32]; if (c->rtt) snprintf(r, sizeof r, "%dms", c->rtt); else snprintf(r, sizeof r, "测量中");
        add(o, "  %s %-9s %-46s 延迟 %s\n", i == best ? "→" : " ", link_kind(c), c->addr, r); n++;
    }
    if (best >= 0) { add(o, "走直连: %s %s\n", link_kind(&G.c[best]), G.c[best].addr); return; }
    int k = route(ed, NULL, 0);
    if (k >= 0) add(o, "没有直连, 经 %s 中转(到它 %s, 延迟 %dms)\n", name_of(G.c[k].peer), link_kind(&G.c[k]), G.c[k].rtt);
    else add(o, "不通: 没有直连, 也没有能中转的%s\n", n ? "" : "(对方不在线?)");
}

static const char *kind_json(const conn_t *c) { return c->udp ? "udp" : c->fam == 6 ? "tcp6" : "tcp4"; }

/* netcheck --json: 字段名英文, 状态说明原样(中文)放在 *_state 里给人看 */
void netcheck_json(buf_t *o)
{
    char ips[16][48], tp[200], up[200], v6[64]; int ni = p_local_ipv4s(ips, 16);
    add(o, "{\"name\":"); json_str(o, G.name);
    add(o, ",\"capability\":\"%s\",\"local_addrs\":[", G.r4 && G.r6 ? "dualstack" : G.r4 ? "public" : G.r6 ? "ipv6" : G.punch[0] || G.upunch[0] ? "p2p" : "relay");
    for (int k = 0; k < ni; k++) { if (k) add(o, ","); json_str(o, ips[k]); }
    add(o, "],\"tcp_in\":{\"ok\":%s,\"addr\":", G.r4 ? "true" : "false"); json_str(o, G.r4 ? relay_addr() : "");
    add(o, ",\"state\":"); json_str(o, G.port_state);
    add(o, "},\"udp_in\":{\"ok\":%s,\"state\":", G.uin_ok ? "true" : "false"); json_str(o, G.uin_state);
    add(o, "},\"upnp\":{\"tcp_port\":%d,\"udp_port\":%d,\"why\":", G.upnp_port, G.upnp_udp); json_str(o, G.upnp_off ? "off" : G.upnp_why);
    int has6 = !local_ip6(v6, sizeof v6);
    add(o, "},\"ipv6\":{\"addr\":"); json_str(o, has6 ? v6 : "");
    add(o, ",\"ok\":%s,\"state\":", G.r6 ? "true" : "false"); json_str(o, G.port6_state);
    punch_desc(tp, up, sizeof tp);
    add(o, "},\"punch\":{\"tcp\":"); json_str(o, G.punch); add(o, ",\"udp\":"); json_str(o, G.upunch);
    add(o, ",\"tcp_state\":"); json_str(o, tp); add(o, ",\"udp_state\":"); json_str(o, up);
    add(o, "},\"links\":[");
    int first = 1;
    for (int i = 0; i < MAXC; i++) {
        conn_t *c = &G.c[i];
        if (c->state != C_UP || !c->pm) continue;
        add(o, "%s{\"name\":", first ? "" : ","); json_str(o, c->pm->name);
        add(o, ",\"kind\":\"%s\",\"addr\":", kind_json(c)); json_str(o, c->addr);
        add(o, ",\"rtt_ms\":%d}", c->rtt); first = 0;
    }
    add(o, "]}\n");
}

void ping_json(buf_t *o, const uint8_t ed[32])
{
    int best = conn_by_peer(ed), first = 1;
    add(o, "{\"links\":[");
    for (int i = 0; i < MAXC; i++) {
        conn_t *c = &G.c[i];
        if (c->state != C_UP || memcmp(c->peer, ed, 32)) continue;
        add(o, "%s{\"kind\":\"%s\",\"addr\":", first ? "" : ",", kind_json(c)); json_str(o, c->addr);
        add(o, ",\"rtt_ms\":%d,\"chosen\":%s}", c->rtt, i == best ? "true" : "false"); first = 0;
    }
    add(o, "],\"route\":");
    if (best >= 0) add(o, "\"direct\"");
    else { int k = route(ed, NULL, 0); if (k >= 0) { add(o, "{\"via\":"); json_str(o, name_of(G.c[k].peer)); add(o, "}"); } else add(o, "null"); }
    add(o, "}\n");
}

void netcheck_text(buf_t *o)
{
    char ips[16][48], tp[200], up[200], v6[64]; int ni = p_local_ipv4s(ips, 16);
    add(o, "本机 %s, 能力: %s\n", G.name, G.r4 && G.r6 ? "双栈" : G.r4 ? "公网" : G.r6 ? "IPv6" : G.punch[0] || G.upunch[0] ? "P2P" : "跳转");
    add(o, "本机地址:"); for (int k = 0; k < ni; k++) add(o, " %s", ips[k]); add(o, "%s\n", ni ? "" : " (没有)");
    add(o, "TCP 入站: %s\n", G.port_state[0] ? G.port_state : "检测中");
    add(o, "UDP 入站: %s\n", G.ufd < 0 ? "没开 UDP" : G.uin_state[0] ? G.uin_state : G.upnp_port ? "UPnP 没映射上 UDP" : "没有映射(连不进来的靠打洞)");
    char um[80]; snprintf(um, sizeof um, G.upnp_udp ? "已映射 TCP %d、UDP %d" : "已映射 TCP %d(UDP 没映射上)", G.upnp_port, G.upnp_udp);
    add(o, "UPnP: %s\n", G.upnp_off ? "关(conf upnp off)" : G.upnp_port ? um : G.upnp_why[0] ? G.upnp_why : "检测中");
    add(o, "IPv6: %s\n", local_ip6(v6, sizeof v6) ? "本机没有公网 IPv6" : G.port6_state[0] ? G.port6_state : v6);
    punch_desc(tp, up, sizeof tp);
    add(o, "TCP 打洞: %s\nUDP 打洞: %s\n", tp, up);
    add(o, "直连:\n");
    for (int t = 0; t < G.trust.n; t++) {
        member_t *m = &G.trust.m[t]; char l[400] = ""; size_t ll = 0;
        if (!memcmp(m->ed, G.id.ed, 32)) continue;
        for (int i = 0; i < MAXC; i++) {
            conn_t *c = &G.c[i];
            if (c->state != C_UP || memcmp(c->peer, m->ed, 32)) continue;
            if (c->rtt) ll += (size_t)snprintf(l + ll, sizeof l - ll, " %s %dms", link_kind(c), c->rtt); else ll += (size_t)snprintf(l + ll, sizeof l - ll, " %s", link_kind(c));
        }
        if (ll) add(o, "  %-10s%s\n", m->name, l);
    }
}

void ls_text(buf_t *o)
{
    char id[9]; short_id(G.id.ed, id);
    add(o, "本机 %s(%s…) %s, 名单 v%ld, 版本 %s%s\n", G.name, id, G.me_relay ? "可达" : "节点", G.trust.ver, CH_VERSION,
        member_by_ed(G.id.ed) ? "" : ", 还没被批准");
    add(o, "端口: %s\n", G.port_state[0] ? G.port_state : "检测中");
    if (G.port6_state[0]) add(o, "IPv6: %s\n", G.port6_state);
    add(o, "能力: %s\n", G.r4 && G.r6 ? "双栈" : G.r4 ? "公网" : G.r6 ? "IPv6" : G.punch[0] || G.upunch[0] ? "P2P" : "跳转");   /* 本机自己的能力(界面用, 和别人从记录里算的一致) */
    if (!G.r4 && G.punch_port) add(o, "打洞: %s\n", G.punch[0] ? G.punch : "没有可用的打洞端点(还在查, 或对称型 NAT)");
    if (G.ufd >= 0 && G.uin_state[0]) add(o, "UDP 入站: %s\n", G.uin_state);
    if (G.ufd >= 0 && !G.uin_ok) add(o, "UDP 打洞: %s\n", G.upunch[0] ? G.upunch : "没有可用的打洞端点(还在查, 可达节点 UDP 不通, 或对称型 NAT)");
    add(o, "挂着:\n");
    for (int t = 0; t < G.nt; t++) {
        int c = conn_by_peer(G.t[t].ed);
        int c4 = conn_by_peer_fam(G.t[t].ed, 4), c6 = conn_by_peer_fam(G.t[t].ed, 6);
        (void)c;
        const char *a4 = c4 >= 0 ? G.c[c4].addr : G.t[t].addr[0] ? G.t[t].addr : G.t[t].nep ? G.t[t].ep[0] : "";   /* 通了显示实际连上的那个地址 */
        if (a4[0]) add(o, "  %-10s %-22s %s\n", G.t[t].name, a4, c4 >= 0 ? "通" : G.t[t].why);
        char v6[64];
        if (G.t[t].addr6[0] && !local_ip6(v6, sizeof v6)) add(o, "  %-10s %-22s %s\n", G.t[t].name, G.t[t].addr6, c6 >= 0 ? "通" : G.t[t].why6);
    }
    add(o, "链路:\n");
    for (int i = 0; i < MAXC; i++) if (G.c[i].state == C_UP)
        add(o, "  %-10s %s %s\n", name_of(G.c[i].peer), G.c[i].udp ? "UDP" : G.c[i].punch ? "打洞" : G.c[i].initiator ? "出站" : "入站", G.c[i].addr);
    add(o, "位置记录:\n");
    int64_t now = now_ms();
    for (int i = 0; i < G.nr; i++) {
        rec_t *r = &G.r[i];
        add(o, "  %-10s %s 地址=%s 挂在=%s 状态=%s 机器=%s 版本=%s(%lds 前收到)%s%s\n", name_of(r->ed), r->relay ? "可达" : "节点",
            r->addr, r->relays, r->status, r->info[0] ? r->info : "-", r->ver, (long)((now - r->rx_ms) / 1000), r->addr6[0] ? " IPv6=" : "", r->addr6);
        if (r->eps[0]) { o->len--; add(o, " 端点=%s\n", r->eps); }
        if (r->punch[0]) { o->len--; add(o, " 打洞=%s\n", r->punch); }
        if (r->upunch[0]) { o->len--; add(o, " UDP打洞=%s\n", r->upunch); }
    }
}

/* ---------- 命令行一侧 ---------- */
int ctl_open_raw(const char *dir)
{
    char p[300], t[4096], ctl[64] = "";
    p_init();
    snprintf(p, sizeof p, "%s/conf", dir);
    if (m_read(p, t, sizeof t) < 0) {
        if (!p_group_member()) { char u[100]; p_username(u, sizeof u);
            fprintf(stderr, "账号 %s 不在 custhub 组里, 用不了本机的 custhub。\n  请管理员执行: sudo custhub user add %s(加完重新登录); 或者这次先用 sudo custhub …\n", u, u); }
        else fprintf(stderr, "读不了 %s(本机还没接入? 先 custhub join)\n", p);
        return -1;
    }
    char *s = strstr(t, "ctl ");
    if (!s || (s != t && s[-1] != '\n') || sscanf(s + 4, "%63s", ctl) != 1) { fprintf(stderr, "conf 里没有 ctl\n"); return -1; }
    char host[64]; int port;
    if (hostport(ctl, host, sizeof host, &port)) return -1;
    char tok[64] = "", why[64];
    snprintf(p, sizeof p, "%s/ctl.token", dir);
    if (m_read(p, tok, sizeof tok) < 32) {
        if (!p_group_member()) {
            char u[100]; p_username(u, sizeof u);
            fprintf(stderr, "账号 %s 不在 custhub 组里, 用不了本机的 custhub。\n  请管理员执行: sudo custhub user add %s(加完重新登录); 或者这次先用 sudo custhub …\n", u, u);
        } else if (!G.quiet) fprintf(stderr, "读不了控制口令牌 %s(守护没在跑?)\n", p);
        return -1;
    }
    tok[strcspn(tok, "\r\n")] = 0;
    int fd = p_dial(host, port, 0, why, sizeof why);
    if (fd < 0) { if (!G.quiet) fprintf(stderr, "连不上本机网络守护(%s): %s\n", ctl, why); return -1; }
    char l[80]; int n = snprintf(l, sizeof l, "AUTH %s\n", tok);
    if (p_send(fd, l, (size_t)n) != n) { p_close(fd); return -1; }
    return fd;
}

int cmd_ctl(const char *dir, const char *line)    /* 发一行命令, 打印回答(管理脚本用) */
{
    int fd = ctl_open_raw(dir);
    if (fd < 0) return 1;
    size_t n = strlen(line);
    if (p_send(fd, line, n) != (long)n || p_send(fd, "\n", 1) != 1) return 1;
    char b[4096]; long r; int err = 0, first = 1;
    while ((r = p_recv(fd, b, sizeof b)) > 0) { if (first && !strncmp(b, "ERR", 3)) err = 1; first = 0; fwrite(b, 1, (size_t)r, stdout); }
    return err;
}

int cmd_ls(const char *dir)
{
    int fd = ctl_open_raw(dir);
    if (fd < 0) return 1;
    if (p_send(fd, "LS\n", 3) != 3) return 1;
    char b[4096]; long r;
    while ((r = p_recv(fd, b, sizeof b)) > 0) fwrite(b, 1, (size_t)r, stdout);
    return 0;
}


int ctl_open(const char *dir, const char *target, const char *req)
{
    int fd = ctl_open_raw(dir);
    if (fd < 0) return -1;
    char l[160]; int n = snprintf(l, sizeof l, "CONNECT %s %s\n", target, req);
    if (p_send(fd, l, n) != n) { p_close(fd); return -1; }
    char resp[200]; size_t k = 0;
    while (k < sizeof resp - 1) { long r = p_recv(fd, resp + k, 1); if (r <= 0) break; if (resp[k++] == '\n') break; }
    resp[k] = 0;
    if (strncmp(resp, "OK\n", 3)) { fprintf(stderr, "mesh %s: %s", strcmp(req, "sh") ? "connect" : "sh", k ? resp : "守护没回话\n"); p_close(fd); return -1; }
    return fd;
}

int cmd_info(const char *dir, const char *target, const char *req)   /* 只读查看: 把对方回的文字原样打印 */
{
    int fd = ctl_open(dir, target, req);
    if (fd < 0) return 1;
    char b[8192]; long r;
    while ((r = p_recv(fd, b, sizeof b)) > 0) fwrite(b, 1, (size_t)r, stdout);
    p_close(fd);
    return 0;
}

int cmd_connect(const char *dir, const char *target, const char *port)
{
    int fd = ctl_open(dir, target, port);
    if (fd < 0) return 1;
    return p_pump_stdio(fd);
}

/* 通行证一览(custhub pass): one = 刚装上的那张(只说它), 否则本机存的全部 */
void pass_text(buf_t *o, const char *one, size_t olen)
{
    static char t[PASSMAX + 1]; static pass_t P; char why[160], p[1300];
    int64_t now = wall_ms() / 1000; int shown = 0;
    if (!one) add(o, "本机 %s 的通行证:\n", G.name);
    for (int k = one ? -1 : 0; k < (one ? 0 : PASSSLOTS); k++) {
        long n;
        if (k < 0) { n = (long)olen; memcpy(t, one, olen); t[olen] = 0; }
        else {
            if (k) snprintf(p, sizeof p, "%s/pass.%d", G.dir, k); else snprintf(p, sizeof p, "%s/pass", G.dir);
            n = m_read(p, t, sizeof t);
        }
        if (n <= 0 || pass_parse(t, (size_t)n, G.master, &P, why, sizeof why)) continue;
        char tos[400] = ""; size_t tl = 0;
        if (P.to_all) snprintf(tos, sizeof tos, "所有机器");
        else for (int i = 0; i < P.nto && tl < sizeof tos - 40; i++) tl += (size_t)snprintf(tos + tl, sizeof tos - tl, "%s%s", i ? "," : "", name_of(P.to[i]));
        int64_t left = P.until - now;
        char st[60];
        if (P.from > now + PASSSKEW) snprintf(st, sizeof st, "还没生效");
        else if (left <= 0) snprintf(st, sizeof st, "已过期");
        else snprintf(st, sizeof st, "还剩 %d 小时 %d 分", (int)(left / 3600), (int)(left % 3600 / 60));
        add(o, "%s进 %s, 用 %s, %s\n", one ? "已装上: " : "  ", tos, P.svc, st);
        if (one) { add(o, "现在可以: custhub sh %s\n", P.to_all ? "<机器>" : name_of(P.to[0])); return; }
        shown++;
    }
    if (!shown) add(o, "  (没有) 请管理员签一张: custhub key pass --for %s --to <机器>\n", G.name);
}
