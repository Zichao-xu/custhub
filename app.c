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
    char cmd[16], a[64], b[16];
    int f = sscanf(q->line, "%15s %63s %15s", cmd, a, b);
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
        for (int i = 0; i < MAXC; i++) if (G.c[i].state == C_UP && !G.c[i].closing && G.c[i].peer_relay) { conn_send(i, F_PENDQ, 0, d, (size_t)dn); n++; }
        if (!n) { put_str(fd, "ERR 没有连着的可达节点\n"); p_close(fd); return; }
        G.pq_fd = fd; G.pq_wait = n; G.pq_deadline = now_ms() + 4000; G.pq_out.len = 0;
        return;
    }
    if (f >= 1 && !strcmp(cmd, "QUIT")) {                /* custhub remove 用: 正常退出(退出码 0, 服务管理器不当失败重启) */
        put_str(fd, "OK 退出\n"); p_close(fd);
        logf_("收到 QUIT, 退出");
        exit(0);
    }
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
        char req[16];
        if (!strcmp(b, "sh")) snprintf(req, sizeof req, "sh");
        else snprintf(req, sizeof req, "port:%d", port);
        if (resolve(a, ed)) { put_str(fd, "ERR 名单里没有这个节点\n"); p_close(fd); return; }
        if ((strcmp(b, "sh") && (port <= 0 || port > 65535)) || hop_open_local(fd, ed, req)) { put_str(fd, "ERR 参数不对或流满了\n"); p_close(fd); }
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

void ls_text(buf_t *o)
{
    char id[9]; short_id(G.id.ed, id);
    add(o, "本机 %s(%s…) %s, 名单 v%ld, 版本 %s%s\n", G.name, id, G.me_relay ? "可达" : "节点", G.trust.ver, CH_VERSION,
        member_by_ed(G.id.ed) ? "" : ", 还没被批准");
    add(o, "端口: %s\n", G.port_state[0] ? G.port_state : "检测中");
    if (G.port6_state[0]) add(o, "IPv6: %s\n", G.port6_state);
    add(o, "挂着:\n");
    for (int t = 0; t < G.nt; t++) {
        int c = conn_by_peer(G.t[t].ed);
        int c4 = conn_by_peer_fam(G.t[t].ed, 4), c6 = conn_by_peer_fam(G.t[t].ed, 6);
        (void)c;
        const char *a4 = c4 >= 0 ? G.c[c4].addr : G.t[t].addr[0] ? G.t[t].addr : G.t[t].nep ? G.t[t].ep[0] : "";   /* 通了显示实际连上的那个地址 */
        if (a4[0]) add(o, "  %-10s %-22s %s\n", G.t[t].name, a4, c4 >= 0 ? "通" : G.t[t].why);
        if (G.t[t].addr6[0]) add(o, "  %-10s %-22s %s\n", G.t[t].name, G.t[t].addr6, c6 >= 0 ? "通" : G.t[t].why6);
    }
    add(o, "链路:\n");
    for (int i = 0; i < MAXC; i++) if (G.c[i].state == C_UP)
        add(o, "  %-10s %s %s\n", name_of(G.c[i].peer), G.c[i].initiator ? "出站" : "入站", G.c[i].addr);
    add(o, "位置记录:\n");
    int64_t now = now_ms();
    for (int i = 0; i < G.nr; i++) {
        rec_t *r = &G.r[i];
        add(o, "  %-10s %s 地址=%s 挂在=%s 状态=%s 机器=%s 版本=%s(%lds 前收到)%s%s\n", name_of(r->ed), r->relay ? "可达" : "节点",
            r->addr, r->relays, r->status, r->info[0] ? r->info : "-", r->ver, (long)((now - r->rx_ms) / 1000), r->addr6[0] ? " IPv6=" : "", r->addr6);
        if (r->eps[0]) { o->len--; add(o, " 端点=%s\n", r->eps); }
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
