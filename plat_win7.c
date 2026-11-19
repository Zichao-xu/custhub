/* Windows 版本模块: Win7 / 8 / 8.1(design-v3 §0 第 7 条: Win7 是补丁模块, 不进主线)
 * 这些系统没有 ConPTY, 交互 shell 只能用管道接 cmd: cmd 不回显键入、也不认方向键, 这里在守护这一侧做一层行编辑:
 *   键入的字当场回显给对方; 退格、Ctrl-U 删改; 方向键等转义序列吞掉; 回车时把整行交给 cmd
 *   cmd 从管道读到一行会自己再显示一遍(提示符后面), 所以回车时先把回显的这一行擦掉, 屏幕上只留 cmd 显示的那份
 *   Ctrl-C 打不断 cmd 里正在跑的命令(没有控制台信号), 只清掉正在输入的这一行; Ctrl-D(空行时) = exit
 * 编译: 和 plat_win.c 一起链, 用 mingw-w64 的 msvcrt(Win7 自带; UCRT 要装补丁), 见 build.sh */
#include "plat_win.h"
#include <string.h>

#define LMAX 1000                 /* 一行最多多少字节(擦除回显时按显示宽度来, 留够余量) */
typedef struct { char line[LMAX + 1]; int n, esc, cr; } lst_t;

static int cpw(unsigned c)        /* 终端里占几格: 中日韩、全角 2 格 */
{
    return (c >= 0x1100 && c <= 0x115F) || (c >= 0x2E80 && c <= 0xA4CF) || (c >= 0xAC00 && c <= 0xD7A3) ||
           (c >= 0xF900 && c <= 0xFAFF) || (c >= 0xFE30 && c <= 0xFE4F) || (c >= 0xFF00 && c <= 0xFF60) || (c >= 0xFFE0 && c <= 0xFFE6) ? 2 : 1;
}

/* 行尾最后一个字: 占几个字节、显示几格 */
static int last_char(const lst_t *s, int *w)
{
    int k = s->n;
    if (!k) { *w = 0; return 0; }
    int st = k - 1;
    while (st > 0 && ((unsigned char)s->line[st] & 0xC0) == 0x80) st--;
    const unsigned char *p = (const unsigned char *)s->line + st;
    unsigned c = *p; int len = k - st;
    if (len > 1) { c &= (unsigned)(0x7F >> len); for (int i = 1; i < len; i++) c = c << 6 | (p[i] & 63); }
    *w = cpw(c);
    return len;
}

static void put(char *b, int *n, const char *s, int k) { memcpy(b + *n, s, (size_t)k); *n += k; }

static void erase(char *echo, int *ne, int w)    /* 往回擦 w 格 */
{
    for (int i = 0; i < w; i++) put(echo, ne, "\b", 1);
    for (int i = 0; i < w; i++) put(echo, ne, " ", 1);
    for (int i = 0; i < w; i++) put(echo, ne, "\b", 1);
}

static int line_width(lst_t *s)
{
    int w = 0, save = s->n, cw;
    while (s->n) { int len = last_char(s, &cw); w += cw; s->n -= len; }
    s->n = save;
    return w;
}

static void line_edit(void *st, const char *in, int n, char *to_child, int *nc, char *echo, int *ne)
{
    lst_t *s = st; *nc = *ne = 0;
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if (s->esc == 1) { s->esc = (c == '[' || c == 'O') ? 2 : 0; continue; }
        if (s->esc == 2) { if (c >= 0x40 && c <= 0x7E) s->esc = 0; continue; }
        if (c == 27) { s->esc = 1; continue; }
        if (c == '\n' && s->cr) { s->cr = 0; continue; }          /* 对方发的 \r\n 只算一次回车 */
        s->cr = c == '\r';
        if (c == '\r' || c == '\n') {
            erase(echo, ne, line_width(s));                       /* cmd 会自己把这行显示一遍 */
            put(to_child, nc, s->line, s->n); put(to_child, nc, "\r\n", 2);
            s->n = 0;
        } else if (c == 0x7F || c == 8) {
            int w, len = last_char(s, &w);
            if (len) { s->n -= len; erase(echo, ne, w); }
        } else if (c == 3 || c == 0x15) {                         /* Ctrl-C / Ctrl-U: 清掉正在输入的这一行 */
            erase(echo, ne, line_width(s)); s->n = 0;
        } else if (c == 4) {                                      /* Ctrl-D: 空行时退出 */
            if (!s->n) put(to_child, nc, "exit\r\n", 6);
        } else if (c < 32 && c != '\t') {
            continue;
        } else if (s->n < LMAX) {
            s->line[s->n++] = (char)c; put(echo, ne, (const char *)&c, 1);
        }
    }
}

const winmod_t WINMOD = { "win7", line_edit, sizeof(lst_t) };
