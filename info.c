/* 远程只读查看(custhub netcheck <名字> / custhub log <名字>): 对方内置 "info:…" 服务, 只读, 权限是通行证里有 info 或 sh
 *   info:netcheck            对方的 netcheck(入站、UPnP、IPv6、打洞、各直连延迟)
 *   info:ls                  对方的 ls(守护原始状态)
 *   info:log:<行数>:<关键字>  对方日志最后几行(只要含关键字的; 关键字里的空格写成 %20)
 *   一次性: 把文字写完就关 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXI 8
static struct { int used, fd, shut; buf_t out; int64_t end; } I[MAXI];

/* 日志最后 lines 行(含 key 的; key 空 = 全部), 最多看日志尾部 1MB */
void log_tail(buf_t *o, int lines, const char *key)
{
    const char *p = log_path();
    if (!p || !p[0]) { buf_add(o, "(没配日志文件)\n", 21); return; }
    void *f = p_fopen(p, "rb");
    if (!f) { buf_add(o, "(读不了日志)\n", 18); return; }
    static char b[1024 * 1024 + 1];
    fseek((FILE *)f, 0, SEEK_END); long sz = ftell((FILE *)f);
    long from = sz > (long)sizeof b - 1 ? sz - (long)sizeof b + 1 : 0;
    fseek((FILE *)f, from, SEEK_SET);
    size_t n = fread(b, 1, sizeof b - 1, (FILE *)f); fclose((FILE *)f); b[n] = 0;
    char *start = from ? strchr(b, '\n') : b;           /* 从截断处的下一行起 */
    if (!start) return;
    if (from) start++;
    if (lines <= 0 || lines > 5000) lines = 100;
    /* 倒着数出含关键字的 lines 行, 再正着输出 */
    char *e = b + n; int cnt = 0; char *cut = start;
    while (e > start) {
        char *ls = e - 1; while (ls > start && ls[-1] != '\n') ls--;
        if (!key[0] || m_mem(ls, (size_t)(e - ls), key, strlen(key))) { if (++cnt > lines) { cut = e; break; } }
        e = ls;
    }
    for (char *l = cut; l < b + n; ) {
        char *nl = memchr(l, '\n', (size_t)(b + n - l)); char *le = nl ? nl + 1 : b + n;
        if (!key[0] || m_mem(l, (size_t)(le - l), key, strlen(key))) buf_add(o, l, (size_t)(le - l));
        l = le;
    }
}

int info_accept(const char *req, char *why, size_t wcap)
{
    buf_t o = { 0 };
    if (!strcmp(req, "info:netcheck")) netcheck_text(&o);
    else if (!strcmp(req, "info:netcheck:json")) netcheck_json(&o);
    else if (!strcmp(req, "info:ls")) ls_text(&o);
    else if (!strncmp(req, "info:log:", 9)) {
        int lines = atoi(req + 9); const char *k = strchr(req + 9, ':'); char key[128] = ""; size_t kl = 0;
        for (const char *c = k ? k + 1 : ""; *c && kl < sizeof key - 1; c++) {   /* %20 → 空格, %25 → % */
            if (c[0] == '%' && c[1] == '2' && (c[2] == '0' || c[2] == '5')) { key[kl++] = c[2] == '0' ? ' ' : '%'; c += 2; }
            else key[kl++] = *c;
        }
        key[kl] = 0;
        log_tail(&o, lines, key);
    } else { snprintf(why, wcap, "不认识的查看请求"); return -1; }
    for (int k = 0; k < MAXI; k++) if (!I[k].used) {
        int sp[2];
        if (p_pair(sp)) { buf_free(&o); snprintf(why, wcap, "开不了通道"); return -1; }
        I[k].used = 1; I[k].fd = sp[1]; I[k].out = o; I[k].shut = 0; I[k].end = now_ms() + 60000;
        return sp[0];
    }
    buf_free(&o); snprintf(why, wcap, "同时查看的太多了");
    return -1;
}

static void iclose(int k) { p_close(I[k].fd); buf_free(&I[k].out); I[k].used = 0; }

void info_poll_add(pfd_t *p, int *np, int *map)
{
    for (int k = 0; k < MAXI; k++) if (I[k].used) { p[*np].fd = I[k].fd; p[*np].ev = (short)(P_IN | (I[k].out.len ? P_OUT : 0)); map[(*np)++] = 9000 + k; }
}

void info_io(int k, short rev)
{
    static uint8_t b[4096];
    if (k < 0 || k >= MAXI || !I[k].used) return;
    if ((rev & P_OUT) && I[k].out.len) {
        long w = p_send(I[k].fd, I[k].out.p, I[k].out.len);
        if (w > 0) buf_eat(&I[k].out, (size_t)w); else if (w == P_FAIL) { iclose(k); return; }
    }
    if (!I[k].out.len && !I[k].shut) { p_shut_wr(I[k].fd); I[k].shut = 1; }   /* 写完: 半关, 等对方收完关 */
    if (rev & (P_IN | P_HUP)) { long r = p_recv(I[k].fd, b, sizeof b); if (r == 0 || r == P_FAIL) iclose(k); }
}

void info_tick(void)
{
    int64_t now = now_ms();
    for (int k = 0; k < MAXI; k++) if (I[k].used && now > I[k].end) iclose(k);
}
