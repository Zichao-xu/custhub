/* custhub exec <目标> [--json] [--timeout 秒] -- 命令…
 *   在一台或多台机器上跑一条命令, 并行, 拿每台的输出和退出码; 输出一样的合并显示, 一眼看出哪台不一样
 *   目标: 名字、逗号分开的几个、分组(@all @online @win @win7 @linux @mac), 能混用("@win7,A-3")
 *   走的是现成的 sh 服务(带命令跑完就退, 回退出码): 对方不用新功能、不用新权限(要有 sh 通行证); 全在发起这头做
 *   输出: 去掉终端控制码(颜色、光标、标题)和回车, 只留文字; 伪终端里标准输出和错误输出是合在一起的 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXX 64
#define XCAP (1024 * 1024)       /* 每台最多收这么多输出 */
typedef struct { char name[32]; int fd, st, code, trunc; buf_t in, out; char err[200]; int64_t t0, ms; } xt_t;   /* st: 0 等 OK, 1 在跑, 2 完 */

static int frame(int fd, int type, const void *p, size_t n)
{
    uint8_t h[3] = { (uint8_t)type, (uint8_t)(n >> 8), (uint8_t)n };
    p_block(fd);
    int bad = p_send(fd, h, 3) != 3 || (n && p_send(fd, p, n) != (long)n);
    p_nb(fd);
    return bad ? -1 : 0;
}

/* 去掉终端控制码和回车, 行尾空白和末尾空行 */
static void clean(buf_t *b)
{
    size_t o = 0, n = b->len; uint8_t *p = b->p;
    for (size_t i = 0; i < n; i++) {
        if (p[i] == 0x1b && i + 1 < n) {
            if (p[i + 1] == '[') { i += 2; while (i < n && !(p[i] >= 0x40 && p[i] <= 0x7e)) i++; continue; }        /* CSI … 终止字节 */
            if (p[i + 1] == ']') { i += 2; while (i < n && p[i] != 7 && !(p[i] == 0x1b && i + 1 < n && p[i + 1] == '\\')) i++; if (i < n && p[i] == 0x1b) i++; continue; }   /* OSC … BEL / ST */
            i += 1; continue;                                                                                     /* 其余两字节的 */
        }
        if (p[i] == '\r' || p[i] == 7) continue;
        p[o++] = p[i];
    }
    size_t w = 0, ls = 0;                               /* 行尾空白 */
    for (size_t i = 0; i < o; i++) {
        if (p[i] == '\n') { while (w > ls && (p[w - 1] == ' ' || p[w - 1] == '\t')) w--; p[w++] = '\n'; ls = w; }
        else p[w++] = p[i];
    }
    while (w && (p[w - 1] == '\n' || p[w - 1] == ' ')) w--;
    b->len = w;
}

static void finish(xt_t *x, const char *err)
{
    if (x->st == 2) return;
    if (err) snprintf(x->err, sizeof x->err, "%s", err);
    x->st = 2; x->ms = now_ms() - x->t0;
    if (x->fd >= 0) { p_close(x->fd); x->fd = -1; }
    clean(&x->out);
}

int cmd_exec(int argc, char **argv)
{
    /* argv: 目录 目标 [--json] [--timeout 秒] -- 命令… */
    const char *dir = argv[0], *tg = argc > 1 ? argv[1] : "";
    int json = 0, tmo = 60, i = 2;
    for (; i < argc && strcmp(argv[i], "--"); i++) {
        if (!strcmp(argv[i], "--json")) json = 1;
        else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) tmo = atoi(argv[++i]);
        else { i = argc; break; }
    }
    if (i >= argc - 1 || tmo <= 0) {
        fprintf(stderr, "用法: custhub exec <目标> [--json] [--timeout 秒] -- 命令…\n"
                        "  目标: 名字 / 逗号分开的几个 / 分组 @all @online @win @win7 @linux @mac(能混用, 如 @win7,A-3)\n"
                        "  要有对方的 sh 通行证; 输出一样的机器合并显示; 全部退出码 0 才返回 0\n");
        return 2;
    }
    static char cmd[15000]; size_t cl = 0;
    for (int k = i + 1; k < argc; k++) {
        size_t l = strlen(argv[k]);
        if (cl + l + 2 >= sizeof cmd) { fprintf(stderr, "命令太长\n"); return 2; }
        if (cl) cmd[cl++] = ' ';
        memcpy(cmd + cl, argv[k], l); cl += l;
    }
    cmd[cl] = 0;
    /* 目标 → 名字(守护有位置记录, 知道谁是什么平台、在不在线) */
    char rq[1100], names[2048]; snprintf(rq, sizeof rq, "TARGETS %s", tg);
    int cfd = ctl_open_raw(dir);
    if (cfd < 0) return 1;
    size_t rl = strlen(rq); rq[rl] = '\n';
    if (p_send(cfd, rq, rl + 1) != (long)(rl + 1)) { p_close(cfd); return 1; }
    size_t nn = 0; long r;
    while (nn < sizeof names - 1 && (r = p_recv(cfd, names + nn, sizeof names - 1 - nn)) > 0) nn += (size_t)r;
    p_close(cfd); names[nn] = 0;
    char *nl = strchr(names, '\n'); if (nl) *nl = 0;
    if (!strncmp(names, "ERR", 3) || !names[0]) { fprintf(stderr, "%s\n", names[0] ? names + 4 : "守护没回话(旧版本?)"); return 2; }
    static xt_t X[MAXX]; int nx = 0;
    char *sv = NULL;
    for (char *t = m_tok(names, " ", &sv); t && nx < MAXX; t = m_tok(NULL, " ", &sv)) {
        xt_t *x = &X[nx++]; memset(x, 0, sizeof *x);
        snprintf(x->name, sizeof x->name, "%s", t); x->fd = -1; x->t0 = now_ms();
        x->fd = ctl_open_raw(dir);
        if (x->fd < 0) { finish(x, "连不上本机守护"); continue; }
        char l[120]; int ln = snprintf(l, sizeof l, "CONNECT %s sh\n", t);
        if (p_send(x->fd, l, (size_t)ln) != ln) { finish(x, "连不上本机守护"); continue; }
        p_nb(x->fd);
    }
    static uint8_t b[65536];
    int64_t end = now_ms() + (int64_t)tmo * 1000;
    for (;;) {
        pfd_t q[MAXX]; int map[MAXX], nq = 0;
        for (int k = 0; k < nx; k++) if (X[k].st < 2) { q[nq].fd = X[k].fd; q[nq].ev = P_IN; q[nq].rev = 0; map[nq++] = k; }
        if (!nq) break;
        if (now_ms() > end) { for (int k = 0; k < nq; k++) finish(&X[map[k]], "超时"); break; }
        if (p_poll(q, nq, 200) < 0) break;
        for (int j = 0; j < nq; j++) {
            if (!q[j].rev) continue;
            xt_t *x = &X[map[j]];
            r = p_recv(x->fd, b, sizeof b);
            if (r == P_AGAIN) continue;
            if (r <= 0) { finish(x, x->st == 0 ? "守护断开了" : "连接断了(命令还没跑完)"); continue; }
            buf_add(&x->in, b, (size_t)r);
            if (x->st == 0) {                            /* 第一行: OK / ERR */
                uint8_t *e = memchr(x->in.p, '\n', x->in.len);
                if (!e) continue;
                size_t ll = (size_t)(e - x->in.p);
                if (ll < 2 || memcmp(x->in.p, "OK", 2)) {
                    char m[200]; size_t k = ll < sizeof m - 1 ? ll : sizeof m - 1; memcpy(m, x->in.p, k); m[k] = 0;
                    finish(x, !strncmp(m, "ERR ", 4) ? m + 4 : m); continue;
                }
                buf_eat(&x->in, ll + 1); x->st = 1;
                char o[15200]; int ol = snprintf(o, sizeof o, "50 400 dumb\n%s", cmd);   /* 宽一点, 免得伪终端折行 */
                if (frame(x->fd, 'O', o, (size_t)ol) || frame(x->fd, 'E', NULL, 0)) { finish(x, "发不出去"); continue; }
            }
            size_t off = 0;                              /* 帧: 'D' 输出, 'X' 退出码 */
            while (x->st == 1 && x->in.len - off >= 3) {
                size_t n = (size_t)x->in.p[off + 1] << 8 | x->in.p[off + 2];
                if (x->in.len - off - 3 < n) break;
                const uint8_t *p = x->in.p + off + 3;
                if (x->in.p[off] == 'D') { if (x->out.len + n <= XCAP) buf_add(&x->out, p, n); else x->trunc = 1; }
                else if (x->in.p[off] == 'X' && n == 4) { x->code = (int)((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]); finish(x, NULL); }
                off += 3 + n;
            }
            if (x->st == 1) buf_eat(&x->in, off);
        }
    }
    int bad = 0;
    for (int k = 0; k < nx; k++) if (X[k].err[0] || X[k].code) bad = 1;
    if (json) {                                          /* 每台一条: 机器、成没成、退出码、输出、错误、耗时 */
        buf_t o = { 0 };
        buf_add(&o, "[", 1);
        for (int k = 0; k < nx; k++) {
            xt_t *x = &X[k]; char h[160];
            buf_add(&x->out, "", 1); x->out.len--;
            int hl = snprintf(h, sizeof h, "%s{\"name\":", k ? "," : ""); buf_add(&o, h, (size_t)hl); json_str(&o, x->name);
            hl = snprintf(h, sizeof h, ",\"ok\":%s,\"code\":%d,\"ms\":%lld,\"truncated\":%s,\"output\":", !x->err[0] && !x->code ? "true" : "false", x->err[0] ? -1 : x->code, (long long)x->ms, x->trunc ? "true" : "false");
            buf_add(&o, h, (size_t)hl); json_str(&o, x->out.len ? (char *)x->out.p : "");
            buf_add(&o, ",\"error\":", 9);
            if (x->err[0]) json_str(&o, x->err); else buf_add(&o, "null", 4);
            buf_add(&o, "}", 1);
        }
        buf_add(&o, "]\n", 2);
        fwrite(o.p, 1, o.len, stdout); buf_free(&o);
    } else {                                             /* 输出和退出码一样的合并成一组 */
        int done[MAXX] = { 0 }; int64_t tmax = 0;
        for (int k = 0; k < nx; k++) if (X[k].ms > tmax) tmax = X[k].ms;
        for (int k = 0; k < nx; k++) {
            if (done[k]) continue;
            xt_t *x = &X[k]; char who[2048]; size_t wl = 0;
            for (int j = k; j < nx; j++) {
                xt_t *y = &X[j];
                if (done[j] || strcmp(y->err, x->err) || y->code != x->code || y->out.len != x->out.len || (x->out.len && memcmp(y->out.p, x->out.p, x->out.len))) continue;
                done[j] = 1;
                wl += (size_t)snprintf(who + wl, sizeof who - wl, "%s%s", wl ? " " : "", y->name);
            }
            if (x->err[0]) printf("── %s  ✘ %s\n", who, x->err);
            else printf("── %s  %s 退出码 %d%s\n", who, x->code ? "✘" : "✔", x->code, x->trunc ? "(输出太长, 截掉了)" : "");
            if (!x->err[0] && x->out.len) { fwrite(x->out.p, 1, x->out.len, stdout); printf("\n"); }
        }
        int ok = 0; for (int k = 0; k < nx; k++) if (!X[k].err[0] && !X[k].code) ok++;
        printf("(%d 台, 成功 %d, %.1f 秒)\n", nx, ok, tmax / 1000.0);
    }
    for (int k = 0; k < nx; k++) { buf_free(&X[k].in); buf_free(&X[k].out); }
    return bad ? 1 : 0;
}
