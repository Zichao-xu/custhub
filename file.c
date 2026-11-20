/* 传文件(custhub send / pull): 对方内置 "file" 服务, 权限和 shell 一样(通行证里有 file 或 sh 都行)
 *   send:  客户端 "PUT <大小> <哈希>\n<对方路径>\n<文件名>\n"  → 服务端 "OK <从哪接着收>\n" | "ERR 原因\n"
 *          客户端发剩下的字节 → 服务端收齐、核对哈希、改名到位 → "DONE\n" | "ERR 原因\n"
 *   pull:  客户端 "GET\n<对方路径>\n" → 服务端 "OK <大小> <哈希> <文件名>\n" | "ERR 原因\n"
 *          客户端 "FROM <从哪开始>\n" → 服务端发到底、关 → 客户端核对哈希、改名到位
 *   断点续传: 没收完的存在 "<目标>.<哈希前 8 位>.custhub-part", 同一个文件(哈希一样)再传就从它的大小接着来
 *   完整性: BLAKE2b-256 整个文件; 不一致不留半截(临时文件), 一致才改名覆盖目标
 *   路径: UTF-8(Windows 上中文、空格都行); 对方路径是已有目录或以 / \ 结尾, 就放进去、用原文件名 */
#include "mesh.h"
#include "vendor/monocypher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXF 8
#define FCHUNK 65536
enum { FS_HEAD, FS_RECV, FS_SEND, FS_DONE };
typedef struct {
    int used, fd, st, get;
    void *f; buf_t in, out;
    char path[1100], part[1200], hash[65];
    int64_t size, got, end;
    crypto_blake2b_ctx h;
} fs_t;
static fs_t F[MAXF];

static void hexof(const uint8_t *b, size_t n, char *o) { for (size_t i = 0; i < n; i++) snprintf(o + 2 * i, 3, "%02x", b[i]); }

/* 整个文件的哈希(读到 upto 字节为止, -1 = 全部), 顺带算进 ctx(续传时把已有的部分先算进去) */
static int hash_file(const char *path, int64_t upto, crypto_blake2b_ctx *ctx, char *hex)
{
    static uint8_t b[FCHUNK]; crypto_blake2b_ctx own; crypto_blake2b_ctx *c = ctx ? ctx : &own;
    if (!ctx) crypto_blake2b_init(c, 32);
    void *f = p_fopen(path, "rb");
    if (!f) return -1;
    int64_t left = upto; size_t r;
    while ((upto < 0 || left > 0) && (r = fread(b, 1, upto < 0 || left > (int64_t)sizeof b ? sizeof b : (size_t)left, (FILE *)f)) > 0) {
        crypto_blake2b_update(c, b, r); left -= (int64_t)r;
    }
    fclose((FILE *)f);
    if (upto > 0 && left > 0) return -1;
    if (hex) { uint8_t d[32]; crypto_blake2b_final(c, d); hexof(d, 32, hex); }
    return 0;
}

static const char *base_of(const char *p)
{
    const char *b = p;
    for (const char *c = p; *c; c++) if (*c == '/' || *c == '\\') b = c + 1;
    return b;
}

/* 目标路径: 给的是已有目录或以分隔符结尾, 就接上文件名 */
static void target_of(const char *dst, const char *name, char *out, size_t cap)
{
    size_t n = strlen(dst);
    int dir = n && (dst[n - 1] == '/' || dst[n - 1] == '\\');
    if (!dir && p_isdir(dst)) dir = 2;
    if (dir) snprintf(out, cap, "%s%s%s", dst, dir == 2 ? (char[]){ p_sep(), 0 } : "", name);
    else snprintf(out, cap, "%s", dst);
}

static int name_ok(const char *n) { return *n && strcmp(n, ".") && strcmp(n, "..") && !strchr(n, '/') && !strchr(n, '\\'); }

/* ---------- 服务端(守护里) ---------- */
int file_accept(char *why, size_t wcap)
{
    for (int k = 0; k < MAXF; k++) if (!F[k].used) {
        int sp[2];
        if (p_pair(sp)) { snprintf(why, wcap, "开不了传文件通道"); return -1; }
        memset(&F[k], 0, sizeof F[k]);
        F[k].used = 1; F[k].fd = sp[1]; F[k].st = FS_HEAD; F[k].end = now_ms() + 30000;
        return sp[0];
    }
    snprintf(why, wcap, "同时传的文件太多了");
    return -1;
}

static void fclose_(int k)
{
    fs_t *x = &F[k];
    if (x->f) fclose((FILE *)x->f);
    p_close(x->fd); buf_free(&x->in); buf_free(&x->out);
    x->used = 0;
}
static void reply(fs_t *x, const char *s) { buf_add(&x->out, s, strlen(s)); }
static void fail(fs_t *x, const char *why) { char l[600]; snprintf(l, sizeof l, "ERR %s\n", why); reply(x, l); x->st = FS_DONE; }

/* 从 in 里取一行(不含换行); 0 = 还没收齐 */
static int take_line(buf_t *in, char *out, size_t cap)
{
    for (size_t i = 0; i < in->len; i++) if (in->p[i] == '\n') {
        size_t n = i < cap - 1 ? i : cap - 1;
        memcpy(out, in->p, n); out[n] = 0;
        if (n && out[n - 1] == '\r') out[n - 1] = 0;
        buf_eat(in, i + 1);
        return 1;
    }
    return 0;
}

static void head(int k)
{
    fs_t *x = &F[k];
    char l1[200], l2[1024], l3[300];
    size_t keep = x->in.len; (void)keep;
    if (!memchr(x->in.p, '\n', x->in.len)) return;
    if (!strncmp((char *)x->in.p, "GET", 3)) {
        int n = 0; for (size_t i = 0; i < x->in.len; i++) if (x->in.p[i] == '\n') n++;
        if (n < 2) return;
        take_line(&x->in, l1, sizeof l1); take_line(&x->in, l2, sizeof l2);
        x->get = 1;
        x->size = p_fsize(l2);
        if (x->size < 0) { fail(x, p_isdir(l2) ? "对方路径是目录(一次只传一个文件)" : "对方没有这个文件"); return; }
        if (hash_file(l2, -1, NULL, x->hash)) { fail(x, "读不了这个文件"); return; }
        snprintf(x->path, sizeof x->path, "%s", l2);
        char r[400]; snprintf(r, sizeof r, "OK %lld %s %s\n", (long long)x->size, x->hash, base_of(l2));
        reply(x, r); x->st = FS_HEAD;                     /* 等 FROM */
        return;
    }
    if (!strncmp((char *)x->in.p, "FROM ", 5) && x->get) {
        take_line(&x->in, l1, sizeof l1);
        int64_t from = atoll(l1 + 5);
        if (from < 0 || from > x->size) { fail(x, "续传位置不对"); return; }
        x->f = p_fopen(x->path, "rb");
        if (!x->f || p_fseek64(x->f, from)) { fail(x, "读不了这个文件"); return; }
        logf_("传文件: 发出 %s(从 %lld 字节起, 共 %lld)", x->path, (long long)from, (long long)x->size);
        x->st = FS_SEND; return;
    }
    if (!strncmp((char *)x->in.p, "PUT ", 4)) {
        int n = 0; for (size_t i = 0; i < x->in.len; i++) if (x->in.p[i] == '\n') n++;
        if (n < 3) return;
        take_line(&x->in, l1, sizeof l1); take_line(&x->in, l2, sizeof l2); take_line(&x->in, l3, sizeof l3);
        long long sz; char hx[80];
        if (sscanf(l1, "PUT %lld %79s", &sz, hx) != 2 || sz < 0 || strlen(hx) != 64 || !name_ok(l3) || !l2[0]) { fail(x, "请求不对"); return; }
        x->size = sz; snprintf(x->hash, sizeof x->hash, "%s", hx);
        target_of(l2, l3, x->path, sizeof x->path);
        if (p_isdir(x->path)) { fail(x, "对方这个路径是目录"); return; }
        char pth[1100], hh[16]; memcpy(pth, x->path, sizeof pth); memcpy(hh, x->hash, 8); hh[8] = 0;
        snprintf(x->part, sizeof x->part, "%s.%s.custhub-part", pth, hh);
        int64_t have = p_fsize(x->part);                  /* 续传: 同一个文件没收完的部分 */
        if (have < 0 || have > x->size) have = 0;
        crypto_blake2b_init(&x->h, 32);
        if (have && hash_file(x->part, have, &x->h, NULL)) have = 0, crypto_blake2b_init(&x->h, 32);
        x->f = p_fopen(x->part, have ? "ab" : "wb");
        if (!x->f) { fail(x, "对方写不了这个路径(目录不存在或没权限)"); return; }
        x->got = have;
        char r[80]; snprintf(r, sizeof r, "OK %lld\n", (long long)have); reply(x, r);
        logf_("传文件: 收 %s(%lld 字节%s)", x->path, (long long)x->size, have ? ", 续传" : "");
        x->st = FS_RECV;
        return;
    }
    if (x->in.len > 2048) fail(x, "请求不对");
}

static void recv_more(int k)
{
    fs_t *x = &F[k];
    if (!x->in.len) return;
    size_t n = x->in.len;
    if ((int64_t)n > x->size - x->got) n = (size_t)(x->size - x->got);
    if (n && fwrite(x->in.p, 1, n, (FILE *)x->f) != n) { fail(x, "对方写盘失败(满了?)"); return; }
    crypto_blake2b_update(&x->h, x->in.p, n);
    x->got += (int64_t)n; buf_eat(&x->in, x->in.len);
    if (x->got < x->size) return;
    fclose((FILE *)x->f); x->f = NULL;
    uint8_t d[32]; char hx[65]; crypto_blake2b_final(&x->h, d); hexof(d, 32, hx);
    if (strcmp(hx, x->hash)) { p_remove(x->part); fail(x, "收到的内容和原文件对不上(已丢弃, 重传一次)"); return; }
    if (p_replace(x->part, x->path)) { fail(x, "收齐了但放不到目标位置(被占用? 没权限?)"); return; }
    logf_("传文件: 收好 %s", x->path);
    reply(x, "DONE\n"); x->st = FS_DONE;
}

void file_poll_add(pfd_t *p, int *np, int *map)
{
    for (int k = 0; k < MAXF; k++) if (F[k].used) {
        short ev = (short)(P_IN | (F[k].out.len || F[k].st == FS_SEND ? P_OUT : 0));
        p[*np].fd = F[k].fd; p[*np].ev = ev; map[(*np)++] = 8000 + k;
    }
}

void file_io(int k, short rev)
{
    static uint8_t b[FCHUNK];
    if (k < 0 || k >= MAXF || !F[k].used) return;
    fs_t *x = &F[k];
    if (rev & (P_IN | P_HUP)) {
        long r = p_recv(x->fd, b, sizeof b);
        if (r == 0 || r == P_FAIL) {                     /* 对方关了: 没收完的留着续传 */
            if (x->st == FS_RECV && x->got < x->size) logf_("传文件: %s 断在 %lld / %lld 字节, 留着续传", x->path, (long long)x->got, (long long)x->size);
            fclose_(k); return;
        }
        if (r > 0) {
            buf_add(&x->in, b, (size_t)r); x->end = now_ms() + 120000;
            if (x->st == FS_HEAD) head(k);
            if (x->st == FS_RECV) recv_more(k);
        }
    }
    if (!x->used) return;
    if ((rev & P_OUT) && x->out.len) {
        long w = p_send(x->fd, x->out.p, x->out.len);
        if (w > 0) buf_eat(&x->out, (size_t)w); else if (w == P_FAIL) { fclose_(k); return; }
    }
    if ((rev & P_OUT) && x->st == FS_SEND && !x->out.len) {
        size_t r = fread(b, 1, sizeof b, (FILE *)x->f);
        if (r > 0) { long w = p_send(x->fd, b, r); if (w == P_FAIL) { fclose_(k); return; } if (w > 0 && (size_t)w < r) buf_add(&x->out, b + w, r - (size_t)w); if (w == P_AGAIN) buf_add(&x->out, b, r); x->end = now_ms() + 120000; }
        else { p_shut_wr(x->fd); x->st = FS_DONE; }
    }
    if (x->st == FS_DONE && !x->out.len) p_shut_wr(x->fd);
}

void file_tick(void)
{
    int64_t now = now_ms();
    for (int k = 0; k < MAXF; k++) if (F[k].used && now > F[k].end) fclose_(k);   /* 两分钟没动静就收(没收完的留着续传) */
}

/* ---------- 客户端(custhub send / pull) ---------- */
static int line_in(int fd, char *out, size_t cap)
{
    size_t k = 0; char c;
    while (k < cap - 1) { long r = p_recv(fd, &c, 1); if (r <= 0) return -1; if (c == '\n') break; out[k++] = c; }
    out[k] = 0; return 0;
}

static void progress(int64_t done, int64_t total, int64_t t0, int fin)
{
    static int64_t last; static int tty = -1;
    if (tty < 0) tty = p_stderr_tty();
    int64_t now = now_ms();
    if (!fin && (!tty || now - last < 500)) return;      /* 不在终端里(脚本、AI 调用): 不刷进度, 只给最后一行 */
    last = now;
    double s = (now - t0) / 1000.0 + 0.001;
    fprintf(stderr, "%s  %5.1f%%  %lld / %lld MB  %.2f MB/s   ", tty ? "\r" : "", total ? done * 100.0 / total : 100.0, (long long)(done >> 20), (long long)(total >> 20), done / s / 1048576.0);
    if (fin) fprintf(stderr, "\n");
}

int cmd_send(const char *dir, const char *local, const char *who, const char *rpath)
{
    int64_t size = p_fsize(local);
    if (size < 0) { fprintf(stderr, p_isdir(local) ? "%s 是目录(一次只传一个文件)\n" : "本机没有这个文件: %s\n", local); return 1; }
    char hx[65]; if (p_stderr_tty()) fprintf(stderr, "  核对用的哈希…\r");
    if (hash_file(local, -1, NULL, hx)) { fprintf(stderr, "读不了 %s\n", local); return 1; }
    int fd = ctl_open(dir, who, "file");
    if (fd < 0) return 1;
    char h[1600]; int n = snprintf(h, sizeof h, "PUT %lld %s\n%s\n%s\n", (long long)size, hx, rpath, base_of(local));
    if (p_send(fd, h, (size_t)n) != n) { fprintf(stderr, "发不出去\n"); return 1; }
    char l[700];
    if (line_in(fd, l, sizeof l) || strncmp(l, "OK ", 3)) { fprintf(stderr, "对方拒绝: %s\n", strncmp(l, "ERR ", 4) ? l : l + 4); p_close(fd); return 1; }
    int64_t from = atoll(l + 3);
    void *f = p_fopen(local, "rb");
    if (!f || p_fseek64(f, from)) { fprintf(stderr, "读不了 %s\n", local); return 1; }
    if (from) fprintf(stderr, "  接着上次的 %lld MB 续传\n", (long long)(from >> 20));
    static uint8_t b[FCHUNK]; size_t r; int64_t done = from, t0 = now_ms();
    const char *dly = getenv("CUSTHUB_SEND_DELAY_MS");   /* 测试用: 每块之间停一下, 好在半截掐断 */
    while ((r = fread(b, 1, sizeof b, (FILE *)f)) > 0) {
        if (dly) p_sleep_ms(atoi(dly));
        if (p_send(fd, b, r) != (long)r) { fprintf(stderr, "\n传到一半断了(再执行一次同样的命令会接着传)\n"); fclose((FILE *)f); return 1; }
        done += (int64_t)r; progress(done, size, t0, 0);
    }
    fclose((FILE *)f); progress(done, size, t0, 1);
    if (line_in(fd, l, sizeof l)) { fprintf(stderr, "对方没回确认(连接断了?), 再执行一次会续传\n"); return 1; }
    p_close(fd);
    if (strcmp(l, "DONE")) { fprintf(stderr, "对方: %s\n", strncmp(l, "ERR ", 4) ? l : l + 4); return 1; }
    printf("已发到 %s: %s\n", who, rpath);
    return 0;
}

int cmd_pull(const char *dir, const char *local, const char *who, const char *rpath)
{
    int fd = ctl_open(dir, who, "file");
    if (fd < 0) return 1;
    char h[1200]; int n = snprintf(h, sizeof h, "GET\n%s\n", rpath);
    if (p_send(fd, h, (size_t)n) != n) { fprintf(stderr, "发不出去\n"); return 1; }
    char l[700], hx[80], nm[400];
    long long size;
    if (line_in(fd, l, sizeof l) || sscanf(l, "OK %lld %79s %399[^\n]", &size, hx, nm) != 3) { fprintf(stderr, "对方: %s\n", strncmp(l, "ERR ", 4) ? l : l + 4); p_close(fd); return 1; }
    char path[1100], part[1200];
    target_of(local, nm, path, sizeof path);
    snprintf(part, sizeof part, "%s.%.8s.custhub-part", path, hx);
    int64_t have = p_fsize(part);
    if (have < 0 || have > size) have = 0;
    void *f = p_fopen(part, have ? "ab" : "wb");
    if (!f) { fprintf(stderr, "本机写不了 %s\n", part); return 1; }
    if (have) fprintf(stderr, "  接着上次的 %lld MB 续传\n", (long long)(have >> 20));
    n = snprintf(h, sizeof h, "FROM %lld\n", (long long)have);
    if (p_send(fd, h, (size_t)n) != n) { fclose((FILE *)f); return 1; }
    static uint8_t b[FCHUNK]; long r; int64_t done = have, t0 = now_ms();
    while (done < size && (r = p_recv(fd, b, sizeof b)) > 0) {
        if (fwrite(b, 1, (size_t)r, (FILE *)f) != (size_t)r) { fprintf(stderr, "\n本机写盘失败\n"); fclose((FILE *)f); return 1; }
        done += r; progress(done, size, t0, 0);
    }
    fclose((FILE *)f); p_close(fd); progress(done, size, t0, 1);
    if (done < size) { fprintf(stderr, "传到一半断了(再执行一次同样的命令会接着传)\n"); return 1; }
    char got[65];
    if (hash_file(part, -1, NULL, got) || strcmp(got, hx)) { p_remove(part); fprintf(stderr, "收到的内容和原文件对不上(已丢弃, 重传一次)\n"); return 1; }
    if (p_replace(part, path)) { fprintf(stderr, "收齐了但放不到 %s(被占用? 没权限?)\n", path); return 1; }
    printf("已拉到本机: %s\n", path);
    return 0;
}
