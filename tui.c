/* custhub 不带参数: 终端界面(design-v3 §0 第 20 条)
 *   数据都问本机守护(控制口 LS / TRUST), 管理动作交给 custhub 自己的子命令(子进程跑, 输出收回来显示), 不另写一套逻辑
 *   没解锁主钥匙: 只显示本机卡片 + 按钮(解锁 / 本机通行证 / 装通行证 / 退出); 网里别的机器一概不显示
 *   解锁(界面里弹窗输口令)后: 机器列表、开 shell、待批准 / 批准、签通行证、新客户接入、移出名单、上锁
 * 只用 ANSI 转义序列(Windows 10 控制台由平台模块开 VT 模式), 不依赖 curses */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

typedef struct { char name[32], code[8], key[48], addr[64], via[96], status[128], ver[16], host[64], plat[24], os[64], model[64]; int relay, rec, link, link4, link6, linku, self, punch; long age; char addr6[80], tp[64], up[64]; } row_t;
typedef struct { char code[8], key[48], from[80], host[64], plat[24], ver[16]; } pend_t;

static row_t RW[MAXM]; static int nrw;
static void set_info(row_t *r, const char *mi);
static pend_t PD[32]; static int npd;
static char my6[200] = "", mycap[16] = "", mytp[200] = "", myup[200] = "";   /* 本机 IPv6 / 能力 / TCP、UDP 打洞(ls 的那几行) */        /* 本机能力(ls 的 "能力: …") */                            /* 本机 IPv6 那一行(ls 的 "IPv6: …") */
static char tdir[1200], tself[1200], me[64] = "?", info[200] = "", msg[600] = "", mykey[48] = "";
static int unlocked, sel, top, rows = 24, cols = 80, msg_err;
static int64_t t_ls, t_status, t_pend;
static int watching; static char watch_base[1024]; static int64_t watch_end;

/* ---------- 输出 ---------- */
static buf_t S;
static void out(const char *fmt, ...)
{
    char t[2048]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(t, sizeof t, fmt, ap); va_end(ap);
    if (n > 0) buf_add(&S, t, (size_t)n < sizeof t ? (size_t)n : sizeof t - 1);
}
static void flush_out(void) { p_stdout_write(S.p, S.len); S.len = 0; }

static int cp_width(unsigned c)                         /* 终端里占几格: 中日韩、全角 2 格 */
{
    return (c >= 0x1100 && c <= 0x115F) || (c >= 0x2E80 && c <= 0xA4CF) || (c >= 0xAC00 && c <= 0xD7A3) ||
           (c >= 0xF900 && c <= 0xFAFF) || (c >= 0xFE30 && c <= 0xFE4F) || (c >= 0xFF00 && c <= 0xFF60) || (c >= 0xFFE0 && c <= 0xFFE6) ? 2 : 1;
}
/* 按显示宽度截断 / 补空格到 w 格 */
static void cell(const char *s, int w)
{
    int used = 0; const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        unsigned c = *p; int len = 1;
        if (c >= 0xF0) { c &= 7; len = 4; } else if (c >= 0xE0) { c &= 15; len = 3; } else if (c >= 0xC0) { c &= 31; len = 2; }
        for (int i = 1; i < len && p[i]; i++) c = c << 6 | (p[i] & 63);
        int cw = cp_width(c);
        if (used + cw > w) break;
        buf_add(&S, p, (size_t)len); used += cw; p += len;
    }
    for (; used < w; used++) buf_add(&S, " ", 1);
}

/* ---------- 取数据 ---------- */
static long ctl_get(const char *cmd, char *b, size_t cap)
{
    G.quiet = 1;
    int fd = ctl_open_raw(tdir);
    if (fd < 0) return -1;
    size_t l = strlen(cmd);
    if (p_send(fd, cmd, l) != (long)l || p_send(fd, "\n", 1) != 1) { p_close(fd); return -1; }
    size_t n = 0; long r;
    while (n < cap - 1 && (r = p_recv(fd, b + n, cap - 1 - n)) > 0) n += (size_t)r;
    p_close(fd); b[n] = 0;
    return (long)n;
}

/* 跑 custhub 自己的子命令, 收标准输出 + 错误输出 */
static int self_run(char *o, size_t cap, ...)
{
    const char *av[16]; int k = 0; va_list ap; va_start(ap, cap);
    av[k++] = tself;
    for (const char *a; k < 15 && (a = va_arg(ap, const char *)); ) av[k++] = a;
    va_end(ap); av[k] = NULL;
    int r = p_run(av, o, cap, 30);
    return r;
}

static void last_line(const char *o, char *dst, size_t cap)    /* 输出里最后一行非空的 */
{
    const char *e = o + strlen(o);
    while (e > o && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ')) e--;
    const char *b = e; while (b > o && b[-1] != '\n') b--;
    while (*b == ' ') b++;
    snprintf(dst, cap, "%.*s", (int)(e - b), b);
}

static void set_msg(int err, const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    msg_err = err;
}

static void load_ls(void)
{
    static char t[MAXTEXT + 1024], l[32768];
    if (ctl_get("TRUST", t, sizeof t) < 0) { set_msg(1, "连不上本机守护(custhub 服务没在跑?)"); return; }
    if (ctl_get("LS", l, sizeof l) < 0) return;
    {                                                    /* 告警: 只看该告诉人的事件(离线太久、版本卡住、能力变差), 显示在提示行 */
        static long evl = -1; static char e[16384];
        if (evl < 0) { if (ctl_get("EVENTS -1", e, sizeof e) >= 0) evl = atol(e); }
        else { char q[40]; snprintf(q, sizeof q, "EVENTS %ld", evl);
            if (ctl_get(q, e, sizeof e) >= 0) { char *sv2 = NULL;
                for (char *ln = m_tok(e, "\n", &sv2); ln; ln = m_tok(NULL, "\n", &sv2)) {
                    long id; long long ts; char nm[32], ty[16], fr[40], to[40];
                    if (sscanf(ln, "%ld %lld %31s %15s %39s %39s", &id, &ts, nm, ty, fr, to) != 6) continue;
                    evl = id; char m[200];
                    if (!strcmp(ty, "offline_long")) snprintf(m, sizeof m, "告警: %s 离线超过 10 分钟", nm);
                    else if (!strcmp(ty, "behind")) snprintf(m, sizeof m, "告警: %s 版本卡在 %s(网里已是 %s)", nm, fr, to);
                    else if (!strcmp(ty, "capability") && (!strcmp(to, "relay") || (!strcmp(to, "p2p") && strcmp(fr, "relay")))) snprintf(m, sizeof m, "告警: %s 能力变差 %s → %s", nm, fr, to);
                    else continue;
                    set_msg(1, m);
                } } }
    }
    int was = sel; char wasn[32] = ""; if (was < nrw) snprintf(wasn, sizeof wasn, "%s", RW[was].name);
    nrw = 0; my6[0] = 0; mycap[0] = 0; mytp[0] = 0; myup[0] = 0;
    char *sv = NULL;
    for (char *ln = m_tok(t, "\n", &sv); ln && nrw < MAXM; ln = m_tok(NULL, "\n", &sv)) {
        char k[8], nm[32], kb[48], ad[64] = "";
        int f = sscanf(ln, "%7s %31s %47s %63s", k, nm, kb, ad);
        if (f < 3 || (strcmp(k, "relay") && strcmp(k, "node"))) continue;
        row_t *r = &RW[nrw++]; memset(r, 0, sizeof *r);
        snprintf(r->name, sizeof r->name, "%s", nm); snprintf(r->key, sizeof r->key, "%s", kb);
        r->relay = !strcmp(k, "relay"); snprintf(r->addr, sizeof r->addr, "%s", ad);
        uint8_t ed[32]; if (b64_decode(kb, strlen(kb), ed, 32) == 32) join_code(ed, r->code);
        const char *h = strstr(ln, " host="); if (h) sscanf(h + 6, "%63s", r->host);
    }
    sv = NULL; int sec = 0;
    for (char *ln = m_tok(l, "\n", &sv); ln; ln = m_tok(NULL, "\n", &sv)) {
        if (!strncmp(ln, "IPv6: ", 6)) { snprintf(my6, sizeof my6, "%s", ln + 6); continue; }
        if (!strncmp(ln, "能力: ", 8)) { snprintf(mycap, sizeof mycap, "%s", ln + 8); continue; }
        if (!strncmp(ln, "打洞: ", 8)) { snprintf(mytp, sizeof mytp, "%s", ln + 8); continue; }
        if (!strncmp(ln, "UDP 打洞: ", 12)) { snprintf(myup, sizeof myup, "%s", ln + 12); continue; }
        if (!strncmp(ln, "本机 ", 7)) {
            sscanf(ln + 7, "%63[^(]", me);
            snprintf(info, sizeof info, "%s", ln);
            continue;
        }
        if (!strcmp(ln, "链路:")) { sec = 1; continue; }
        if (!strcmp(ln, "位置记录:")) { sec = 2; continue; }
        if (ln[0] != ' ') { sec = 0; continue; }
        char nm[32];
        if (sscanf(ln, " %31s", nm) != 1) continue;
        row_t *r = NULL; for (int i = 0; i < nrw; i++) if (!strcmp(RW[i].name, nm)) r = &RW[i];
        if (!r) continue;
        if (sec == 1) {                                 /* "  名字  出站/入站  地址": 本机和它有哪几种链路 */
            char dir_[16], la[96] = "";
            r->link = 1;
            int f = sscanf(ln, " %*s %15s %95s", dir_, la);
            if (f == 2 && !strcmp(dir_, "UDP")) r->linku = 1; else if (f == 2 && la[0] == '[') r->link6 = 1; else r->link4 = 1;
        }
        else if (sec == 2) {
            char ad[64] = "", via[96] = "", st[128] = "", vr[16] = "", mi[200] = ""; long age = 0;
            const char *mm = strstr(ln, "机器=");
            if (mm) sscanf(mm + 7, "%199s", mi);
            if (mi[0] && strcmp(mi, "-")) set_info(r, mi);
            const char *a = strstr(ln, "地址="), *b = strstr(ln, "挂在="), *c = strstr(ln, "状态="), *d = strstr(ln, "版本=");
            if (a) sscanf(a + 7, "%63s", ad);
            if (b) sscanf(b + 7, "%95s", via);
            if (c) sscanf(c + 7, "%127s", st);
            if (d) sscanf(d + 7, "%15[^(](%lds", vr, &age);
            r->rec = 1; r->age = age;
            r->relay = strstr(ln, " 可达 ") != NULL;         /* 可达看它自己的声明(自检), 不看名单 */
            if (strcmp(ad, "-")) snprintf(r->addr, sizeof r->addr, "%s", ad);
            r->punch = strstr(ln, "打洞=") != NULL;        /* 报了打洞端点(TCP 的 " 打洞=" 或 " UDP打洞=") */
            const char *tp = strstr(ln, " 打洞="), *up = strstr(ln, " UDP打洞=");
            if (tp) sscanf(tp + 8, "%63s", r->tp);
            if (up) sscanf(up + 11, "%63s", r->up);
            const char *v6 = strstr(ln, " IPv6=[");      /* IPv6 可达地址 */
            if (v6) sscanf(v6 + 6, "%79s", r->addr6);
            snprintf(r->via, sizeof r->via, "%s", via); snprintf(r->status, sizeof r->status, "%s", st); snprintf(r->ver, sizeof r->ver, "%s", vr);
        }
    }
    for (int i = 0; i < nrw; i++) if (!strcmp(RW[i].name, me) || (RW[i].key[0] && !strcmp(RW[i].key, mykey))) { RW[i].self = 1; snprintf(RW[i].ver, sizeof RW[i].ver, "%s", CH_VERSION); set_info(&RW[i], my_info()); }
    if (wasn[0]) for (int i = 0; i < nrw; i++) if (!strcmp(RW[i].name, wasn)) sel = i;
    t_ls = now_ms();
}

static void load_status(void)
{
    static char o[2048];
    self_run(o, sizeof o, "key", "--dir", tdir, "status", (const char *)NULL);
    unlocked = !strncmp(o, "已解锁", 9);
    t_status = now_ms();
}

static void load_pending(void)
{
    static char o[16384];
    t_pend = now_ms();
    if (!unlocked) { npd = 0; return; }
    self_run(o, sizeof o, "key", "--dir", tdir, "pending", (const char *)NULL);
    npd = 0;
    char *sv = NULL;
    for (char *ln = m_tok(o, "\n", &sv); ln && npd < 32; ln = m_tok(NULL, "\n", &sv)) {
        pend_t p; memset(&p, 0, sizeof p);
        /* "  接入码  公钥  来自 地址(经 可达节点)  机器名 平台 版本" */
        if (sscanf(ln, " %7s %47s", p.code, p.key) != 2 || strlen(p.code) != 7 || p.code[3] != '-') continue;
        const char *f = strstr(ln, "来自 "), *e = f ? strstr(f, ")") : NULL;
        if (!f) continue;
        sscanf(f + 7, "%79[^(]", p.from);
        if (e) sscanf(e + 1, "%63s %23s %15s", p.host, p.plat, p.ver);
        int dup = 0; for (int i = 0; i < npd; i++) if (!strcmp(PD[i].code, p.code)) dup = 1;
        if (!dup) PD[npd++] = p;
    }
    if (watching) {                                     /* 新客户接入: 等点完之后新冒出来的 */
        for (int i = 0; i < npd; i++) if (!strstr(watch_base, PD[i].code)) {
            watching = 0; sel = nrw + i;
            set_msg(0, "新机器报到: %s %s(%s), 按 a 批准", PD[i].code, PD[i].host, PD[i].plat);
            break;
        }
        if (watching && now_ms() > watch_end) { watching = 0; set_msg(1, "30 分钟没有新机器报到, 不等了"); }
    }
}

/* 平台|机器名|系统|机型(_ 是空格) → 各列 */
static void set_info(row_t *r, const char *mi)
{
    char b[200]; snprintf(b, sizeof b, "%s", mi);
    char *s6 = strstr(b, "|6="); if (s6) *s6 = 0;      /* IPv6、局域网端点那几段不是机器信息 */
    char *se = strstr(b, "|e="); if (se) *se = 0;
    char *sp = strstr(b, "|p="); if (sp) *sp = 0;
    char *su = strstr(b, "|u="); if (su) *su = 0;
    for (char *c = b; *c; c++) if (*c == '_') *c = ' ';
    char *f[4] = { b, "", "", "" }; int k = 1;
    for (char *c = b; *c && k < 4; c++) if (*c == '|') { *c = 0; f[k++] = c + 1; }
    snprintf(r->plat, sizeof r->plat, "%s", f[0]);
    if (f[1][0]) snprintf(r->host, sizeof r->host, "%s", f[1]);
    snprintf(r->os, sizeof r->os, "%s", f[2]); snprintf(r->model, sizeof r->model, "%s", f[3]);
}

/* ---------- 画 ---------- */
static int online(const row_t *r) { return r->self || r->link || (r->rec && r->age < 150 && strstr(r->status, ":up")); }

static void draw(void)
{
    p_tty_size(&rows, &cols);
    if (rows < 8) rows = 8;
    if (cols < 40) cols = 40;
    S.len = 0;
    out("\x1b[H\x1b[2J");
    char head[300];
    snprintf(head, sizeof head, " custhub %s · 本机 %s · 主钥匙: %s%s", CH_VERSION, me, unlocked ? "已解锁" : "未解锁",
             watching ? " · 等新机器报到…" : "");
    out("\x1b[7m"); cell(head, cols); out("\x1b[0m\r\n");
    int wc = cols - 16 - 6 - 18 - 9 - 6;                 /* 系统 / 机型 / 连接 分剩下的宽度 */
    int wos = wc * 30 / 100, wmo = wc * 30 / 100, wcn = wc - wos - wmo;
    out("\x1b[1m"); cell("  名字", 16); cell("状态", 6); cell("机器名", 18); cell("系统", wos); cell("机型", wmo); cell("版本", 9); cell("能力", 6); cell("连接", wcn); out("\x1b[0m\r\n");
    int nitems = nrw + (unlocked ? npd : 0);
    if (sel >= nitems) sel = nitems ? nitems - 1 : 0;
    int area = rows - 7 - (unlocked && npd ? 1 : 0);
    if (sel < top) top = sel;
    if (sel >= top + area) top = sel - area + 1;
    int shown = 0;
    for (int i = top; i < nitems && shown < area; i++, shown++) {
        if (i == nrw) { out("\x1b[1m"); cell("  待批准(按 a 批准)", cols); out("\x1b[0m\r\n"); if (++shown >= area) break; }
        char line[400], conn[200];
        if (i < nrw) {
            row_t *r = &RW[i]; int on = online(r);
            if (r->self) snprintf(conn, sizeof conn, "本机%s", !my6[0] || strstr(my6, "没有 IPv6") ? "" : strstr(my6, ", 可达") ? "(IPv6 可达)" : strstr(my6, "已开启") ? "(IPv6 观察中)" : "(有 IPv6, 外面连不进来)");
            else if (r->link) {                          /* 写明协议: TCP(IPv4 / IPv6) 和 UDP 各有没有 */
                const char *tcp = r->link4 && r->link6 ? "TCP(IPv4+IPv6)" : r->link6 ? "TCP(IPv6)" : r->link4 ? "TCP" : "";
                snprintf(conn, sizeof conn, "直连 %s%s%s%s%s", tcp, tcp[0] && r->linku ? "+" : "", r->linku ? "UDP" : "", r->relay ? " " : "", r->relay ? r->addr : "");
            }
            else if (r->rec && strcmp(r->via, "-")) snprintf(conn, sizeof conn, "经 %s", r->via);
            else snprintf(conn, sizeof conn, "%s", r->relay ? r->addr : "-");
            out(i == sel ? "\x1b[7m" : "");
            snprintf(line, sizeof line, "%s %-13s", i == sel ? ">" : " ", r->name); cell(line, 16);
            out(i == sel ? "" : on ? "\x1b[32m" : "\x1b[2m"); cell(r->self ? "本机" : on ? "在线" : "离线", 6); out(i == sel ? "" : "\x1b[0m");
            char osb[100]; snprintf(osb, sizeof osb, "%s", r->os[0] ? r->os : r->plat[0] ? r->plat : "-");
            cell(r->host[0] ? r->host : "-", 18); cell(osb, wos); cell(r->model[0] ? r->model : "-", wmo);
            cell(r->ver[0] ? r->ver : "-", 9);
            /* 能力: 每台按自己报的算(谁看都一样): 双栈 > 公网 > IPv6 > P2P(能打洞) > 跳转(只能中转) */
            int v4 = r->relay && addr_fam(r->addr) == 4, v6 = r->addr6[0] == '[';
            const char *cap = r->self ? (mycap[0] ? mycap : "-") : !r->rec ? "-" : v4 && v6 ? "双栈" : v4 ? "公网" : v6 ? "IPv6" : r->punch ? "P2P" : "跳转";
            cell(cap, 6);
            cell(conn, wcn);
            out("\x1b[0m\r\n");
        } else {
            pend_t *p = &PD[i - nrw];
            out(i == sel ? "\x1b[7m" : "\x1b[33m");
            snprintf(line, sizeof line, "%s %s  %s  %s  %s  来自 %s", i == sel ? ">" : " ", p->code, p->host, p->plat, p->ver, p->from);
            cell(line, cols); out("\x1b[0m\r\n");
        }
    }
    for (; shown < area; shown++) out("\r\n");
    /* 详情 */
    char det[400] = "";
    if (sel < nrw && nrw) {
        row_t *r = &RW[sel];
        snprintf(det, sizeof det, " %s  接入码 %s  %s%s%s%s  %s  公钥 %.12s…%s", r->name, r->code, r->relay ? "可达 " : "节点", r->relay && addr_fam(r->addr) == 4 ? r->addr : "",
                 r->addr6[0] ? (r->relay && addr_fam(r->addr) == 4 ? "  IPv6 " : "IPv6 ") : "", r->addr6, r->plat[0] ? r->plat : "", r->key, r->rec && !r->self ? "  " : "");
        if (r->rec && !r->self) { size_t l = strlen(det); snprintf(det + l, sizeof det - l, "最近 %lds 前", r->age); }
        if (r->self && my6[0]) { size_t l = strlen(det); snprintf(det + l, sizeof det - l, "  IPv6: %s", my6); }
        const char *tpa = r->self ? mytp : r->tp, *upa = r->self ? myup : r->up;   /* 打洞端点: TCP / UDP */
        if (tpa[0] || upa[0]) { size_t l = strlen(det); snprintf(det + l, sizeof det - l, "  打洞 TCP %s  UDP %s", tpa[0] ? tpa : "-", upa[0] ? upa : "-"); }
    } else if (sel >= nrw && sel - nrw < npd) {
        pend_t *p = &PD[sel - nrw]; snprintf(det, sizeof det, " 待批准 %s  机器名 %s  公钥 %.12s…", p->code, p->host, p->key);
    }
    out("\x1b[2m"); cell("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────", cols); out("\x1b[0m\r\n");
    cell(det, cols); out("\r\n");
    out(msg_err ? "\x1b[31m" : "\x1b[36m"); cell(msg[0] ? msg : "", cols); out("\x1b[0m\r\n");
    out("\x1b[2m");
    cell(" ↑↓ 选  Enter 开 shell  v 本机通行证  i 装通行证  r 刷新  q 退出", cols); out("\r\n");
    cell(" a 批准  s 签通行证  n 新客户接入  d 移出名单  l 上锁", cols);
    out("\x1b[0m");
    flush_out();
}

/* ---------- 没解锁: 只画本机 ----------
 * 没有主钥匙时不给看网里别的机器(名字、地址、系统都算); 只剩本机卡片 + 几个按钮(←→ / Tab 选, Enter 按) */
static const char *LBTN[] = { "解锁主钥匙", "本机通行证", "装通行证", "退出" };
enum { LB_UNLOCK, LB_PASS, LB_INSTALL, LB_QUIT, LB_N };
static int lsel;                                         /* 锁定页选中的按钮 */

static void kv(const char *k, const char *v)             /* 卡片一行: "   键     值" */
{
    if (!v || !v[0]) return;
    out("   \x1b[2m"); cell(k, 9); out("\x1b[0m"); cell(v, cols - 12); out("\r\n");
}

static void buttons(const char *const *lb, int n, int on, int indent)
{
    for (int i = 0; i < indent; i++) out(" ");
    for (int i = 0; i < n; i++) {
        out(i == on ? "\x1b[7m" : "\x1b[2m");
        out("[ %s ]", lb[i]); out("\x1b[0m  ");
    }
    out("\r\n");
}

static void draw_locked(void)
{
    p_tty_size(&rows, &cols);
    if (rows < 8) rows = 8;
    if (cols < 40) cols = 40;
    S.len = 0;
    out("\x1b[H\x1b[2J");
    char head[300];
    snprintf(head, sizeof head, " custhub %s · 本机 %s · 主钥匙: 未解锁", CH_VERSION, me);
    out("\x1b[7m"); cell(head, cols); out("\x1b[0m\r\n\r\n");
    row_t *r = NULL; for (int i = 0; i < nrw; i++) if (RW[i].self) r = &RW[i];
    row_t fb; if (!r) { memset(&fb, 0, sizeof fb); snprintf(fb.name, sizeof fb.name, "%s", me); set_info(&fb, my_info()); r = &fb; }
    char b[200];
    out("   \x1b[1m本机 %s\x1b[0m\r\n\r\n", r->name);
    kv("机器名", r->host); kv("系统", r->os[0] ? r->os : r->plat); kv("机型", r->model);
    kv("版本", CH_VERSION); kv("接入码", r->code); kv("能力", mycap);
    if (r->relay && addr_fam(r->addr) == 4) kv("公网地址", r->addr);
    kv("IPv6", my6);
    if (mytp[0] || myup[0]) { snprintf(b, sizeof b, "TCP %s  UDP %s", mytp[0] ? mytp : "-", myup[0] ? myup : "-"); kv("打洞", b); }
    if (r->key[0]) { snprintf(b, sizeof b, "%.16s…", r->key); kv("公钥", b); }
    out("\r\n");
    buttons(LBTN, LB_N, lsel, 3);
    out("\r\n   \x1b[2m网里其他机器、批准、签通行证要先解锁主钥匙\x1b[0m\r\n");
    out("\x1b[%d;1H", rows - 1);
    out(msg_err ? "\x1b[31m" : "\x1b[36m"); cell(msg[0] ? msg : "", cols); out("\x1b[0m\r\n");
    out("\x1b[2m"); cell(" ←→ / Tab 选  Enter 确定  u 解锁主钥匙  v 本机通行证  i 装通行证  q 退出", cols); out("\x1b[0m");
    flush_out();
}

/* ---------- 输入 ---------- */
static int in_fd;
static long read_key(char *b, size_t cap, int ms)
{
    pfd_t q = { in_fd, P_IN, 0 };
    if (p_poll(&q, 1, ms) <= 0 || !q.rev) return 0;
    long r = p_recv(in_fd, b, cap - 1);
    if (r == P_AGAIN) return 0;
    if (r <= 0) return -1;
    b[r] = 0;
    return r;
}

/* 最底下一行输入; 回车确认(返回 1), Esc / Ctrl-C 取消(返回 0) */
static int prompt(const char *ask, char *val, size_t cap)
{
    size_t n = strlen(val);
    for (;;) {
        S.len = 0;
        out("\x1b[%d;1H\x1b[2K\x1b[33m", rows);
        out("%s", ask); out("\x1b[0m%s\x1b[?25h", val);
        flush_out();
        char b[64]; long r = read_key(b, sizeof b, 60000);
        if (r < 0) return 0;
        for (long i = 0; i < r; i++) {
            unsigned char c = (unsigned char)b[i];
            if (c == '\r' || c == '\n') { S.len = 0; out("\x1b[?25l"); flush_out(); return 1; }
            if (c == 3 || (c == 27 && r == 1)) { S.len = 0; out("\x1b[?25l"); flush_out(); return 0; }
            if (c == 27) break;                         /* 方向键之类: 不管 */
            if (c == 127 || c == 8) { while (n && ((unsigned char)val[n - 1] & 0xC0) == 0x80) n--; if (n) n--; val[n] = 0; continue; }
            if (c >= 32 && n + 1 < cap) { val[n++] = (char)c; val[n] = 0; }
        }
    }
}

static void screen(int on)
{
    S.len = 0;
    if (on) { p_tty_raw(1); out("\x1b[?1049h\x1b[?25l"); }
    else out("\x1b[0m\x1b[?25h\x1b[?1049l");
    flush_out();
    if (!on) p_tty_raw(0);
}

/* 整屏显示一段文字(通行证列表、子命令输出), 按任意键回来 */
static void pager(const char *title, const char *text)
{
    S.len = 0;
    out("\x1b[H\x1b[2J\x1b[7m"); cell(title, cols); out("\x1b[0m\r\n");
    int ln = 1;
    for (const char *p = text; *p && ln < rows - 2; ln++) {
        const char *e = strchr(p, '\n'); size_t l = e ? (size_t)(e - p) : strlen(p);
        const unsigned char *q = (const unsigned char *)p, *qe = q + l;   /* 长行算占几行 */
        int w = 0;
        while (q < qe) {
            int len = *q >= 0xF0 ? 4 : *q >= 0xE0 ? 3 : *q >= 0xC0 ? 2 : 1;
            unsigned c = *q; if (len > 1) { c &= (unsigned)(0x7F >> len); for (int i = 1; i < len && q + i < qe; i++) c = c << 6 | (q[i] & 63); }
            int cw = cp_width(c);
            if (w + cw > cols) { w = 0; if (++ln >= rows - 2) break; }   /* 不插换行: 让终端自己折, 复制出来还是一整行 */
            buf_add(&S, q, (size_t)len); w += cw; q += len;
        }
        out("\r\n");
        p += l; if (*p) p++;
    }
    out("\x1b[%d;1H\x1b[2m 按任意键返回\x1b[0m", rows);
    flush_out();
    char b[64]; read_key(b, sizeof b, 600000);
}

static void osc52(const char *s)                        /* 终端剪贴板(iTerm2 / Windows Terminal / kitty / tmux 等支持) */
{
    static char b64[4096]; size_t n = strlen(s);
    if (n > 2800) return;
    b64_encode((const uint8_t *)s, n, b64);
    S.len = 0; out("\x1b]52;c;%s\x07", b64); flush_out();
}

/* ---------- 动作 ---------- */
static void act_shell(void)
{
    if (sel >= nrw) return;
    row_t *r = &RW[sel];
    if (r->self) { set_msg(1, "这是本机"); return; }
    screen(0);
    printf("\x1b[2J\x1b[H── custhub sh %s(exit 退出, 回到列表) ──\n", r->name); fflush(stdout);
    char *av[3] = { tdir, r->name, NULL };
    int64_t t0 = now_ms();
    int rc = cmd_sh(2, av);
    if (rc == 255 && now_ms() - t0 < 5000) {             /* 没开起来(没有通行证 / 连不上): 停一下让人看清原因 */
        printf("\n按回车返回列表"); fflush(stdout);
        p_tty_raw(1); in_fd = p_stdin_fd(); char b[16]; read_key(b, sizeof b, 600000); p_tty_raw(0);
    }
    screen(1);
    set_msg(rc == 255, rc == 255 ? "%s 的 shell 没开起来(没有通行证? 解锁后按 s 签一张)" : "%s 的 shell 结束了", r->name);
}

static void act_pass_list(void)
{
    static char o[16384];
    self_run(o, sizeof o, "pass", "--dir", tdir, (const char *)NULL);
    pager(" 本机通行证(custhub pass)", o);
}

static void act_pass_install(void)
{
    char f[600] = "";
    if (!prompt(" 通行证文件路径(Esc 取消): ", f, sizeof f) || !f[0]) return;
    static char o[4096];
    int rc = self_run(o, sizeof o, "pass", "--dir", tdir, f, (const char *)NULL);
    char l[400]; last_line(o, l, sizeof l);
    set_msg(rc != 0, "%s", rc ? l : "通行证装上了");
    if (!rc) pager(" 装上通行证", o);
}

/* 解锁弹窗: 口令(不回显, 只显示圆点) / 时长 / [解锁] [取消], Tab ↑↓ 换焦点, Enter 确定, Esc 取消
 * 口令经环境变量 CUSTHUB_PASSPHRASE 交给子命令 key unlock(和命令行同一套逻辑), 跑完立刻清掉 */
static void env_pass(const char *v) { p_setenv("CUSTHUB_PASSPHRASE", v); }

static int u8len(const char *s) { int n = 0; for (; *s; s++) if (((unsigned char)*s & 0xC0) != 0x80) n++; return n; }

static void draw_unlock(const char *ph, const char *hrs, int f, const char *err, int busy)
{
    static const char *ub[] = { "解锁", "取消" };
    int w = cols - 8 < 64 ? cols - 8 : 64, x = (cols - w) / 2 + 1, y = rows / 2 - 4; if (y < 2) y = 2;
    char dots[200]; int nd = u8len(ph); if (nd > w - 16) nd = w - 16;
    size_t k = 0; for (int i = 0; i < nd && k + 4 < sizeof dots; i++) { memcpy(dots + k, "\xe2\x80\xa2", 3); k += 3; } dots[k] = 0;   /* • */
    char l[300];
    S.len = 0;
    for (int i = 0; i < 9; i++) { out("\x1b[%d;%dH\x1b[0m", y + i, x); cell("", w); }      /* 先清出一块 */
    out("\x1b[%d;%dH\x1b[7m", y, x); cell(" 解锁主钥匙", w); out("\x1b[0m");
    out("\x1b[%d;%dH", y + 2, x + 2); out(f == 0 ? "\x1b[1;4m" : "\x1b[2m"); out("口令"); out("\x1b[0m  ");
    snprintf(l, sizeof l, "%s%s", dots, f == 0 && !busy ? "_" : ""); cell(l, w - 10);
    out("\x1b[%d;%dH", y + 3, x + 2); out(f == 1 ? "\x1b[1;4m" : "\x1b[2m"); out("时长"); out("\x1b[0m  ");
    snprintf(l, sizeof l, "%s%s 小时", hrs, f == 1 && !busy ? "_" : ""); cell(l, w - 10);
    out("\x1b[%d;%dH", y + 5, x); buttons(ub, 2, f >= 2 ? f - 2 : -1, 2);
    out("\x1b[%d;%dH", y + 7, x + 2);
    out(busy ? "\x1b[36m" : err[0] ? "\x1b[31m" : "\x1b[2m");
    cell(busy ? "派生主钥匙(要几秒)…" : err[0] ? err : "Tab / ↑↓ 换项  Enter 确定  Esc 取消  Ctrl-U 清空", w - 4);
    out("\x1b[0m");
    flush_out();
}

static void act_unlock(void)
{
    char ph[1024] = "", hrs[16] = "8", err[300] = "";
    int f = 0;
    for (;;) {
        draw_unlock(ph, hrs, f, err, 0);
        char b[256]; long r = read_key(b, sizeof b, 600000);
        if (r < 0) break;
        if (r == 0) continue;
        int go = 0, quit = 0;
        if (!strcmp(b, "\x1b[A") || !strcmp(b, "\x1bOA") || !strcmp(b, "\x1b[Z")) { f = (f + 3) % 4; continue; }
        if (!strcmp(b, "\x1b[B") || !strcmp(b, "\x1bOB") || !strcmp(b, "\t")) { f = (f + 1) % 4; continue; }
        if (f >= 2 && (!strcmp(b, "\x1b[D") || !strcmp(b, "\x1b[C") || !strcmp(b, "\x1bOD") || !strcmp(b, "\x1bOC"))) { f = f == 2 ? 3 : 2; continue; }
        for (long i = 0; i < r && !go && !quit; i++) {
            unsigned char c = (unsigned char)b[i];
            if (c == '\r' || c == '\n') { if (f == 3) quit = 1; else go = 1; break; }
            if (c == 3 || (c == 27 && r == 1)) { quit = 1; break; }
            if (c == 27) break;                          /* 别的转义序列: 不管 */
            if (f >= 2) continue;
            char *v = f == 0 ? ph : hrs; size_t cap = f == 0 ? sizeof ph : sizeof hrs, n = strlen(v);
            if (c == 21) { memset(v, 0, cap); continue; }                         /* Ctrl-U */
            if (c == 127 || c == 8) { while (n && ((unsigned char)v[n - 1] & 0xC0) == 0x80) n--; if (n) n--; v[n] = 0; continue; }
            if (f == 1 && !((c >= '0' && c <= '9') || c == '.')) continue;
            if (c >= 32 && n + 1 < cap) { v[n++] = (char)c; v[n] = 0; }
        }
        if (quit) break;
        if (!go) continue;
        if (!ph[0]) { snprintf(err, sizeof err, "先输口令"); f = 0; continue; }
        if (atof(hrs) <= 0) { snprintf(err, sizeof err, "时长要大于 0"); f = 1; continue; }
        draw_unlock(ph, hrs, f, "", 1);
        static char o[4096];
        env_pass(ph);
        int rc = self_run(o, sizeof o, "key", "--dir", tdir, "unlock", hrs, (const char *)NULL);
        env_pass(NULL);
        memset(ph, 0, sizeof ph);
        if (!rc) {
            load_status(); load_pending(); load_ls();
            sel = 0; top = 0;
            set_msg(!unlocked, unlocked ? "已解锁 %s 小时: 管理功能可以用了" : "子命令说解锁了, 但 ssh-agent 里查不到主钥匙", hrs);
            return;
        }
        last_line(o, err, sizeof err); if (!err[0]) snprintf(err, sizeof err, "没解锁");
        f = 0;
    }
    memset(ph, 0, sizeof ph);
    set_msg(0, "没解锁");
}

static void act_lock(void)
{
    static char o[1024];
    self_run(o, sizeof o, "key", "--dir", tdir, "lock", (const char *)NULL);
    load_status(); npd = 0;
    set_msg(0, "已上锁");
}

static void act_approve(void)
{
    if (sel < nrw || sel - nrw >= npd) { set_msg(1, "先选中下面待批准的一台"); return; }
    pend_t *p = &PD[sel - nrw];
    char nm[64] = "";
    char ask[200]; snprintf(ask, sizeof ask, " 批准 %s(%s), 起名(回车 = 自动编号 A-N, Esc 取消): ", p->code, p->host);
    if (!prompt(ask, nm, sizeof nm)) return;
    static char o[4096]; int rc;
    if (nm[0]) rc = self_run(o, sizeof o, "key", "--dir", tdir, "approve", p->code, nm, (const char *)NULL);
    else rc = self_run(o, sizeof o, "key", "--dir", tdir, "approve", p->code, (const char *)NULL);
    char l[400] = ""; const char *hit = strstr(o, "已批准 ");
    if (hit) { const char *e = strchr(hit, '\n'); snprintf(l, sizeof l, "%.*s", (int)(e ? e - hit : (long)strlen(hit)), hit); } else last_line(o, l, sizeof l);
    set_msg(rc != 0, "%s", l);
    char got[40] = ""; if (hit) sscanf(hit + 10, "%39[^(]", got);
    load_ls(); load_pending();
    for (int i = 0; i < nrw; i++) if (got[0] && !strcmp(RW[i].name, got)) sel = i;
}

static void act_sign(void)
{
    if (sel >= nrw) { set_msg(1, "先选中要进的机器"); return; }
    row_t *r = &RW[sel];
    char who[64] = "", svc[100] = "sh", hrs[16] = "2";
    char ask[200]; snprintf(ask, sizeof ask, " 进 %s 的通行证, 给谁(回车 = 本机, 或名单里的名字): ", r->name);
    if (!prompt(ask, who, sizeof who)) return;
    if (!prompt(" 服务(sh / port:3389 / port:* , 空格分开): ", svc, sizeof svc) || !svc[0]) return;
    if (!prompt(" 几小时(最长 24): ", hrs, sizeof hrs) || !hrs[0]) return;
    static char o[4096]; int rc;
    if (who[0]) rc = self_run(o, sizeof o, "key", "--dir", tdir, "pass", "--to", r->name, "--for", who, "--svc", svc, "--hours", hrs, (const char *)NULL);
    else rc = self_run(o, sizeof o, "key", "--dir", tdir, "pass", "--to", r->name, "--svc", svc, "--hours", hrs, (const char *)NULL);
    char l[400]; last_line(o, l, sizeof l);
    if (rc) { set_msg(1, "%s", l); return; }
    if (who[0]) pager(" 通行证签好了: 把文件发给对方, 对方 custhub pass <文件>", o);
    else set_msg(0, "通行证签好了: 本机进 %s 用 %s, %s 小时(按 Enter 开 shell)", r->name, svc, hrs);
}

static void act_remove(void)
{
    if (sel >= nrw) return;
    row_t *r = &RW[sel];
    if (r->self) { set_msg(1, "不能移出本机"); return; }
    char yn[8] = ""; char ask[200]; snprintf(ask, sizeof ask, " 把 %s 移出名单? 它会马上断开, 要重新接入才能回来。输入 y 确认: ", r->name);
    if (!prompt(ask, yn, sizeof yn) || strcmp(yn, "y")) { set_msg(0, "没移出"); return; }
    static char o[4096];
    int rc = self_run(o, sizeof o, "key", "--dir", tdir, "remove", r->name, (const char *)NULL);
    char l[400]; last_line(o, l, sizeof l);
    set_msg(rc != 0, "%s", l);
    load_ls();
}

static void act_new_client(void)
{
    /* 一行通用(守护给, 见 app.c join_line): 地址是网里一台可达机器的 http://IP:端口(Win7 也能下); Windows 前半段, Mac / Linux 后半段 */
    static char b[1024], text[3200];
    if (ctl_get("LINE", b, sizeof b) <= 0 || !strchr(b, '\n')) { set_msg(1, "本机守护没给接入命令(还是旧版本?)"); return; }
    char *line = strchr(b, '\n'); *line++ = 0;
    char *e = strchr(line, '\n'); if (e) *e = 0;
    osc52(line);
    snprintf(text, sizeof text,
             "接入命令(已试着放进剪贴板; 终端不支持的话, 从下面复制):\n\n%s\n\n"
             "  Windows(7 起): Win+R / cmd / PowerShell 里粘贴运行, 弹 UAC 点\"是\"\n"
             "  Mac / Linux: 终端里粘贴运行(会要一次 sudo 密码)\n"
             "  下载来源: %s\n\n"
             "对方跑起来后, 这里会提示\"新机器报到\", 选中按 a 批准(最多等 30 分钟)。\n", line,
             strcmp(b, "-") ? b : "GitHub(网里没有可达的新版机器; Win7 下不了)");
    pager(" 新客户接入", text);
    watching = 1; watch_end = now_ms() + 1800000;
    size_t n = 0; watch_base[0] = 0;
    for (int i = 0; i < npd && n + 9 < sizeof watch_base; i++) n += (size_t)snprintf(watch_base + n, sizeof watch_base - n, "%s ", PD[i].code);
    set_msg(0, "等新机器报到…(对方跑完接入命令后会出现在\"待批准\"里)");
}

/* ---------- 主循环 ---------- */
int cmd_tui(const char *dir)
{
    snprintf(tdir, sizeof tdir, "%s", dir);
    if (p_self_path(tself, sizeof tself)) { fprintf(stderr, "找不到本程序的路径\n"); return 1; }
    static char probe[256];
    G.quiet = 0;
    int fd = ctl_open_raw(tdir);                        /* 先试一下: 连不上就按普通命令行报原因(不在组里 / 没接入 / 服务没跑) */
    if (fd < 0) return 1;
    p_close(fd); (void)probe;
    G.quiet = 1;
    if (!p_tty_raw(1)) { p_tty_raw(0); fprintf(stderr, "不是终端: custhub help 看命令\n"); return 2; }
    if (!p_tty_ansi()) { p_tty_raw(0); fprintf(stderr, "这个终端不认 ANSI(Win7 控制台), 没有界面: 用命令行(custhub help)\n"); return 2; }
    in_fd = p_stdin_fd();
    screen(1);
    load_ls(); load_status(); load_pending();
    if (!msg[0]) set_msg(0, unlocked ? "主钥匙已解锁: 管理功能可用" : "没解锁: 只显示本机; 解锁后看全网、管理");
    for (;;) {
        int was = unlocked;
        if (unlocked) draw(); else draw_locked();
        char b[64]; long r = read_key(b, sizeof b, 2000);
        if (r < 0) break;
        int64_t now = now_ms();
        if (now - t_ls > 2000) load_ls();
        if (now - t_status > 15000) load_status();
        if (unlocked && now - t_pend > (watching ? 5000 : 20000)) load_pending();
        if (was && !unlocked) { npd = 0; watching = 0; lsel = 0; set_msg(1, "主钥匙过期 / 被上锁了: 只显示本机"); }
        if (r == 0) continue;
        if (!was) {                                      /* 锁定页: 只有按钮 */
            if (!strcmp(b, "\x1b[D") || !strcmp(b, "\x1bOD") || !strcmp(b, "\x1b[A") || !strcmp(b, "\x1bOA") || !strcmp(b, "\x1b[Z") || !strcmp(b, "h") || !strcmp(b, "k")) { lsel = (lsel + LB_N - 1) % LB_N; continue; }
            if (!strcmp(b, "\x1b[C") || !strcmp(b, "\x1bOC") || !strcmp(b, "\x1b[B") || !strcmp(b, "\x1bOB") || !strcmp(b, "\t") || !strcmp(b, "l") || !strcmp(b, "j")) { lsel = (lsel + 1) % LB_N; continue; }
            int a = -1;
            if (b[0] == '\r' || b[0] == '\n') a = lsel;
            else if (b[0] == 'u') a = LB_UNLOCK; else if (b[0] == 'v') a = LB_PASS; else if (b[0] == 'i') a = LB_INSTALL;
            else if (b[0] == 'q' || b[0] == 3) a = LB_QUIT;
            else if (b[0] == 'r') { load_ls(); load_status(); set_msg(0, "刷新了"); }
            if (a == LB_QUIT) break;
            if (a == LB_UNLOCK) act_unlock(); else if (a == LB_PASS) act_pass_list(); else if (a == LB_INSTALL) act_pass_install();
            continue;
        }
        int nitems = nrw + (unlocked ? npd : 0);
        if (!strcmp(b, "\x1b[A") || !strcmp(b, "\x1bOA") || !strcmp(b, "k")) { if (sel > 0) sel--; continue; }
        if (!strcmp(b, "\x1b[B") || !strcmp(b, "\x1bOB") || !strcmp(b, "j")) { if (sel + 1 < nitems) sel++; continue; }
        if (b[0] == 'q' || b[0] == 3) break;
        if (b[0] == '\r' || b[0] == '\n') { if (sel < nrw) act_shell(); else if (unlocked) act_approve(); continue; }
        switch (b[0]) {
        case 'r': load_ls(); load_status(); load_pending(); set_msg(0, "刷新了"); break;
        case 'v': act_pass_list(); break;
        case 'i': act_pass_install(); break;
        case 'u': set_msg(0, "已经解锁了"); break;
        case 'l': act_lock(); lsel = 0; break;
        case 'a': act_approve(); break;
        case 's': act_sign(); break;
        case 'n': act_new_client(); break;
        case 'd': act_remove(); break;
        default: break;
        }
    }
    screen(0);
    return 0;
}
