/* sh 服务(design-v3 §0 第 2 条: 目的是抵达对方的 shell; 不依赖 SSH)
 *   流里跑一层小帧: [类型 1][长度 2][内容], 内容最多 SHCHUNK
 *     工程师 → 机器: 'O' 开 "行 列 TERM\n命令"(命令空 = 交互登录 shell; 必须是第一帧)  'D' 键盘输入  'W' 窗口大小(行 2 + 列 2)  'E' 输入到头
 *     机器 → 工程师: 'D' 屏幕输出  'X' 退出码(4 字节, 有符号)
 *   服务端: 服务层(svc.c)验过通行证后调 sh_accept 拿一个 socket 交给连通层当本地端; 另一头和伪终端都在这里, 接进主事件循环
 *   客户端: mesh sh <目录> <名字> [-- 命令…], 交互时把本地终端切成原始模式 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXSH   16
#define SHCHUNK 16000
#define SHLIM   (256 * 1024)     /* 单向积压超过这个就先不读 */

typedef struct {
    int used, s, pfd, h;          /* s: 和连通层之间那对 socket 的这一头; pfd / h: 伪终端 */
    int started, peof, sent_x, cli_gone, ein;
    int64_t exit_ms;
    buf_t in, to_s, to_p;
} shs_t;
static shs_t S[MAXSH];

static void put_frame(buf_t *b, int type, const void *p, size_t n)
{
    uint8_t h[3] = { (uint8_t)type, (uint8_t)(n >> 8), (uint8_t)n };
    buf_add(b, h, 3); if (n) buf_add(b, p, n);
}

static void sh_free(int k)
{
    shs_t *x = &S[k];
    if (x->h >= 0) p_pty_close(x->h);
    if (x->s >= 0) p_close(x->s);
    buf_free(&x->in); buf_free(&x->to_s); buf_free(&x->to_p);
    memset(x, 0, sizeof *x);
}

int sh_accept(char *why, size_t wcap)
{
    for (int k = 0; k < MAXSH; k++) if (!S[k].used) {
        int fd[2];
        if (p_pair(fd)) { snprintf(why, wcap, "开不了 shell 通道"); return -1; }
        memset(&S[k], 0, sizeof S[k]);
        S[k].used = 1; S[k].s = fd[1]; S[k].h = -1; S[k].pfd = -1;
        return fd[0];
    }
    snprintf(why, wcap, "shell 太多了");
    return -1;
}

static void on_frame(int k, int type, const uint8_t *p, size_t n)
{
    shs_t *x = &S[k];
    if (!x->started) {
        if (type != 'O') { x->cli_gone = 1; return; }
        char t[SHCHUNK + 1], term[48] = "", *nl;
        memcpy(t, p, n); t[n] = 0;
        int rows = 24, cols = 80;
        sscanf(t, "%d %d %47s", &rows, &cols, term);
        if (rows < 1 || rows > 1000) rows = 24;
        if (cols < 1 || cols > 1000) cols = 80;
        for (char *c = term; *c; c++) if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') || *c == '-' || *c == '.')) *c = 0;
        nl = strchr(t, '\n');
        const char *cmd = nl && nl[1] ? nl + 1 : NULL;
        char why[96];
        x->h = p_pty_open(cmd, rows, cols, term, &x->pfd, why, sizeof why);
        x->started = 1;
        if (x->h < 0) {
            char m[140]; int ml = snprintf(m, sizeof m, "custhub sh: %s\r\n", why);
            put_frame(&x->to_s, 'D', m, (size_t)ml);
            uint8_t c[4] = { 0, 0, 0, 127 }; put_frame(&x->to_s, 'X', c, 4); x->sent_x = 1;
            logf_("开 shell 失败: %s", why);
            return;
        }
        logf_("开了 shell(%s, %dx%d)", cmd ? "命令" : "交互", cols, rows);
        return;
    }
    if (type == 'D') buf_add(&x->to_p, p, n);
    else if (type == 'W' && n == 4) p_pty_resize(x->h, p[0] << 8 | p[1], p[2] << 8 | p[3]);
    else if (type == 'E') x->ein = 1;                 /* 等已收到的输入写完再告诉平台模块 */
}

static void parse_in(int k)
{
    shs_t *x = &S[k];
    size_t off = 0;
    while (x->in.len - off >= 3) {
        size_t n = (size_t)x->in.p[off + 1] << 8 | x->in.p[off + 2];
        if (n > SHCHUNK) { x->cli_gone = 1; break; }
        if (x->in.len - off - 3 < n) break;
        on_frame(k, x->in.p[off], x->in.p + off + 3, n);
        off += 3 + n;
    }
    buf_eat(&x->in, off);
}

void sh_poll_add(pfd_t *p, int *np, int *map)
{
    for (int k = 0; k < MAXSH; k++) {
        shs_t *x = &S[k];
        if (!x->used) continue;
        short ev = (short)((x->to_s.len ? P_OUT : 0) | (!x->cli_gone && x->to_p.len < SHLIM ? P_IN : 0));
        if (ev) { p[*np].fd = x->s; p[*np].ev = ev; map[(*np)++] = 3000 + 2 * k; }
        if (x->pfd >= 0 && x->h >= 0) {
            ev = (short)((x->to_p.len ? P_OUT : 0) | (!x->peof && x->to_s.len < SHLIM ? P_IN : 0));
            if (ev) { p[*np].fd = x->pfd; p[*np].ev = ev; map[(*np)++] = 3001 + 2 * k; }
        }
    }
}

void sh_io(int code, short rev)
{
    int k = code / 2, pty = code & 1;
    shs_t *x = &S[k];
    static uint8_t b[SHCHUNK];
    if (!x->used) return;
    if (!pty) {
        if ((rev & P_OUT) && x->to_s.len) {
            long w = p_send(x->s, x->to_s.p, x->to_s.len);
            if (w > 0) buf_eat(&x->to_s, (size_t)w); else if (w == P_FAIL) x->cli_gone = 1;
        }
        if (rev & (P_IN | P_HUP)) {
            long r = p_recv(x->s, b, sizeof b);
            if (r > 0) { buf_add(&x->in, b, (size_t)r); parse_in(k); }
            else if (r == 0 || r == P_FAIL) x->cli_gone = 1;
        }
    } else {
        if ((rev & P_OUT) && x->to_p.len) {
            long w = p_send(x->pfd, x->to_p.p, x->to_p.len);
            if (w > 0) buf_eat(&x->to_p, (size_t)w); else if (w == P_FAIL) x->to_p.len = 0;
        }
        if (x->ein == 1 && !x->to_p.len) { p_pty_eof(x->h); x->ein = 2; }
        if (rev & (P_IN | P_HUP)) {
            long r = p_recv(x->pfd, b, sizeof b);
            if (r > 0) put_frame(&x->to_s, 'D', b, (size_t)r);
            else if (r == 0 || r == P_FAIL) x->peof = 1;
        }
    }
}

void sh_tick(void)
{
    int64_t now = now_ms();
    for (int k = 0; k < MAXSH; k++) {
        shs_t *x = &S[k];
        if (!x->used) continue;
        if (x->cli_gone) { logf_("shell 会话结束(工程师那头走了)"); sh_free(k); continue; }
        if (x->ein == 1 && !x->to_p.len && x->h >= 0) { p_pty_eof(x->h); x->ein = 2; }
        if (x->started && x->h >= 0 && !x->sent_x) {
            int code = 0;
            if (p_pty_exit(x->h, &code)) {
                if (!x->exit_ms) x->exit_ms = now;
                if (x->peof || now - x->exit_ms > 2000) {   /* 输出读完了(或退出后 2 秒还有后台进程占着终端) */
                    uint8_t c[4] = { (uint8_t)(code >> 24), (uint8_t)(code >> 16), (uint8_t)(code >> 8), (uint8_t)code };
                    put_frame(&x->to_s, 'X', c, 4); x->sent_x = 1;
                    logf_("shell 退出(%d)", code);
                }
            }
        }
        if (x->sent_x && !x->to_s.len) { p_shut_wr(x->s); sh_free(k); }
    }
}

/* ---------- 客户端: mesh sh <目录> <名字> [-- 命令…] ---------- */
static int put_all(int fd, const uint8_t *p, size_t n)        /* 写到 socket(非阻塞也写完) */
{
    while (n) {
        long w = p_send(fd, p, n);
        if (w == P_AGAIN) { pfd_t q = { fd, P_OUT, 0 }; p_poll(&q, 1, 1000); continue; }
        if (w <= 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int send_frame(int fd, int type, const void *p, size_t n)
{
    uint8_t h[3] = { (uint8_t)type, (uint8_t)(n >> 8), (uint8_t)n };
    return put_all(fd, h, 3) || (n && put_all(fd, p, n)) ? -1 : 0;
}

int cmd_sh(int argc, char **argv)
{
    if (argc < 2 || (argc > 2 && strcmp(argv[2], "--")) || argc == 3) {
        fprintf(stderr, "用法: mesh sh <目录> <名字> [-- 命令…]\n"); return 2;
    }
    static char cmd[SHCHUNK - 200]; size_t cl = 0;
    for (int i = 3; i < argc; i++) {
        size_t l = strlen(argv[i]);
        if (cl + l + 2 >= sizeof cmd) { fprintf(stderr, "命令太长\n"); return 2; }
        if (cl) cmd[cl++] = ' ';
        memcpy(cmd + cl, argv[i], l); cl += l;
    }
    cmd[cl] = 0;
    int fd = ctl_open(argv[0], argv[1], "sh");
    if (fd < 0) return 255;
    p_nb(fd);
    int tty = !cl && p_tty_raw(1);
    int rows = 24, cols = 80; p_tty_size(&rows, &cols);
    const char *term = getenv("TERM");
    char o[SHCHUNK]; int ol = snprintf(o, sizeof o, "%d %d %s\n%s", rows, cols, term && *term ? term : "xterm-256color", cmd);
    if (send_frame(fd, 'O', o, (size_t)ol)) { p_tty_raw(0); fprintf(stderr, "mesh sh: 发不出去\n"); return 255; }
    static uint8_t b[SHCHUNK]; buf_t in = { 0 };
    int in_open = 1, code = -1, sfd = p_stdin_fd();
    if (sfd < 0) in_open = 0;
    for (;;) {
        pfd_t q[2] = { { fd, P_IN, 0 }, { sfd, P_IN, 0 } };
        int nq = in_open ? 2 : 1;
        if (p_poll(q, nq, 200) < 0) break;
        if (tty && p_tty_resized() && !p_tty_size(&rows, &cols)) {
            uint8_t w[4] = { (uint8_t)(rows >> 8), (uint8_t)rows, (uint8_t)(cols >> 8), (uint8_t)cols };
            send_frame(fd, 'W', w, 4);
        }
        if (in_open && q[1].rev) {
            long r = p_recv(sfd, b, sizeof b < SHCHUNK ? sizeof b : SHCHUNK);
            if (r > 0) { if (send_frame(fd, 'D', b, (size_t)r)) break; }
            else if (r != P_AGAIN) { in_open = 0; send_frame(fd, 'E', NULL, 0); }
        }
        if (q[0].rev) {
            long r = p_recv(fd, b, sizeof b);
            if (r == P_AGAIN) continue;
            if (r <= 0) break;
            buf_add(&in, b, (size_t)r);
            size_t off = 0;
            while (in.len - off >= 3) {
                size_t n = (size_t)in.p[off + 1] << 8 | in.p[off + 2];
                if (in.len - off - 3 < n) break;
                const uint8_t *p = in.p + off + 3;
                if (in.p[off] == 'D') p_stdout_write(p, n);
                else if (in.p[off] == 'X' && n == 4) code = (int)((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]);
                off += 3 + n;
            }
            buf_eat(&in, off);
            if (code >= 0) break;
        }
    }
    p_tty_raw(0);
    buf_free(&in);
    if (code < 0) { fprintf(stderr, "\r\nmesh sh: 连接断了\n"); return 255; }
    return code;
}
