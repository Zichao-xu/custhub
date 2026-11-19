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


/* ---------- 控制台不认 ANSI: 输出翻译(界面、custhub sh 看到的远端输出、普通命令的中文) ----------
 * 文字: UTF-8 → UTF-16 → WriteConsoleW(跟控制台代码页、点阵字体都无关)
 * 控制码: 光标定位 / 移动(H f A B C D)、清屏 / 清行(J K)、颜色(m: 粗、暗、反色、8 色 + 亮色)、光标显隐(?25)、
 *         备用屏幕(?1049: 另开一个屏幕缓冲区, 大小同窗口、不自动折行); OSC(比如剪贴板 52)吞掉; 其他不认的忽略 */
#include <windows.h>

typedef struct { int st; char par[64]; int np; char u8[4]; int nu; } ast_t;   /* st: 0 文字 1 ESC 2 CSI 3 OSC 4 OSC 里的 ESC 5 跳过一个字 */
static HANDLE alt;                                   /* 备用屏幕 */
static WORD def_attr; static int have_def, a_bold, a_dim, a_rev, a_fg = -1, a_bg = -1;
static const int A2W[8] = { 0, 4, 2, 6, 1, 5, 3, 7 };   /* ANSI 色号 → 控制台色号 */

static HANDLE tgt(HANDLE h) { return alt ? alt : h; }

static WORD cur_attr(void)
{
    int fg = a_fg < 0 ? (def_attr & 0x0F) : a_fg, bg = a_bg < 0 ? ((def_attr >> 4) & 0x0F) : a_bg;
    if (a_bold) fg |= 8;
    if (a_dim && a_fg < 0) fg = 8;
    if (a_rev) { int t = fg; fg = bg; bg = t; }
    return (WORD)(fg | bg << 4);
}

/* 备用屏幕不自动折行, 但写过行尾时 Win7 控制台(中文代码页)会把多出来的写回行首附近: 自己按格数截掉
 * 一个字占几格 = 它在控制台代码页里编成几个字节(控制台自己就是这么算的: · ─ ↓ 这类在 936 下占 2 格) */
static int clip(WCHAR *w, int n)
{
    CONSOLE_SCREEN_BUFFER_INFO i;
    if (!GetConsoleScreenBufferInfo(alt, &i)) return n;
    UINT cp = GetConsoleOutputCP(); int dbcs = cp == 932 || cp == 936 || cp == 949 || cp == 950;
    int col = i.dwCursorPosition.X, width = i.dwSize.X, o = 0;
    for (int k = 0; k < n; k++) {
        WCHAR c = w[k]; int cw = 1;
        if (c == '\r' || c == '\n') col = 0;
        else if (c == '\b') { if (col) col--; }
        else if (c >= 0xD800 && c <= 0xDFFF) cw = 1;
        else if (dbcs && c >= 0x80) { char mb[8]; BOOL d = 0; int l = WideCharToMultiByte(cp, 0, &c, 1, mb, sizeof mb, NULL, &d); cw = l == 2 ? 2 : 1; }
        if (c == '\r' || c == '\n' || c == '\b') { w[o++] = c; continue; }
        if (col + cw > width) continue;               /* 超出行宽: 丢掉 */
        w[o++] = c; col += cw;
    }
    return o;
}

static void wtext(HANDLE h, ast_t *s, const char *p, size_t n)
{
    static WCHAR w[4200]; char b[4100]; DWORD wr;
    while (n || s->nu) {
        size_t k = 0;
        memcpy(b, s->u8, (size_t)s->nu); k = (size_t)s->nu; s->nu = 0;
        size_t take = n > sizeof b - k - 4 ? sizeof b - k - 4 : n;
        memcpy(b + k, p, take); k += take; p += take; n -= take;
        size_t cut = k;
        for (size_t j = 1; j <= 3 && j <= k; j++) {             /* 末尾不完整的 UTF-8 字留到下次 */
            unsigned char c = (unsigned char)b[k - j];
            if ((c & 0xC0) == 0x80) continue;
            size_t need = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 1;
            if (need > j) cut = k - j;
            break;
        }
        int wn = MultiByteToWideChar(CP_UTF8, 0, b, (int)cut, w, 4200);
        if (wn > 0 && alt) wn = clip(w, wn);
        if (wn > 0) WriteConsoleW(tgt(h), w, (DWORD)wn, &wr, NULL);
        s->nu = (int)(k - cut); memcpy(s->u8, b + cut, (size_t)s->nu);
        if (!n) break;
    }
}

static void fill(HANDLE h, COORD at, DWORD len)
{
    DWORD n;
    FillConsoleOutputCharacterW(h, L' ', len, at, &n);
    FillConsoleOutputAttribute(h, cur_attr(), len, at, &n);
}

static void alt_screen(HANDLE base, int on)
{
    if (on && !alt) {
        CONSOLE_SCREEN_BUFFER_INFO i;
        if (!GetConsoleScreenBufferInfo(base, &i)) return;
        HANDLE a = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
        if (a == INVALID_HANDLE_VALUE) return;
        COORD sz = { (SHORT)(i.srWindow.Right - i.srWindow.Left + 1), (SHORT)(i.srWindow.Bottom - i.srWindow.Top + 1) };
        SMALL_RECT r = { 0, 0, (SHORT)(sz.X - 1), (SHORT)(sz.Y - 1) };
        SetConsoleWindowInfo(a, TRUE, &r);
        if (!SetConsoleScreenBufferSize(a, sz)) { SetConsoleScreenBufferSize(a, sz); SetConsoleWindowInfo(a, TRUE, &r); }
        SetConsoleMode(a, ENABLE_PROCESSED_OUTPUT);          /* 不自动折行: 界面每行正好写满一行宽再换行 */
        SetConsoleTextAttribute(a, def_attr);
        CONSOLE_CURSOR_INFO ci; if (GetConsoleCursorInfo(base, &ci)) SetConsoleCursorInfo(a, &ci);
        SetConsoleActiveScreenBuffer(a);
        alt = a;
    } else if (!on && alt) {
        SetConsoleActiveScreenBuffer(base);
        CloseHandle(alt); alt = NULL;
    }
}

static void csi(HANDLE base, const char *p, char f)
{
    HANDLE h = tgt(base);
    CONSOLE_SCREEN_BUFFER_INFO i;
    if (!GetConsoleScreenBufferInfo(h, &i)) return;
    int a[16] = { 0 }, na = 0, priv = *p == '?';
    for (const char *q = p + priv; *q && na < 16; q++) {
        if (*q >= '0' && *q <= '9') a[na] = a[na] * 10 + (*q - '0');
        else if (*q == ';') na++;
    }
    if (*p && na < 16) na++;
    SMALL_RECT w = i.srWindow; COORD c = i.dwCursorPosition;
    int n1 = na && a[0] ? a[0] : 1;
    switch (f) {
    case 'H': case 'f': {
        int r = na > 0 && a[0] ? a[0] : 1, col = na > 1 && a[1] ? a[1] : 1;
        c.X = (SHORT)(w.Left + col - 1); c.Y = (SHORT)(w.Top + r - 1);
        if (c.X > w.Right) c.X = w.Right;
        if (c.Y > w.Bottom) c.Y = w.Bottom;
        SetConsoleCursorPosition(h, c); break;
    }
    case 'A': c.Y = (SHORT)(c.Y - n1 < w.Top ? w.Top : c.Y - n1); SetConsoleCursorPosition(h, c); break;
    case 'B': c.Y = (SHORT)(c.Y + n1 > w.Bottom ? w.Bottom : c.Y + n1); SetConsoleCursorPosition(h, c); break;
    case 'C': c.X = (SHORT)(c.X + n1 >= i.dwSize.X ? i.dwSize.X - 1 : c.X + n1); SetConsoleCursorPosition(h, c); break;
    case 'D': c.X = (SHORT)(c.X - n1 < 0 ? 0 : c.X - n1); SetConsoleCursorPosition(h, c); break;
    case 'G': c.X = (SHORT)(n1 - 1 >= i.dwSize.X ? i.dwSize.X - 1 : n1 - 1); SetConsoleCursorPosition(h, c); break;
    case 'J': {
        int m = na ? a[0] : 0; COORD top = { 0, w.Top };
        DWORD all = (DWORD)i.dwSize.X * (DWORD)(w.Bottom - w.Top + 1);
        DWORD before = (DWORD)(c.Y - w.Top) * (DWORD)i.dwSize.X + (DWORD)c.X;
        if (m == 2 || m == 3) fill(h, top, all);
        else if (m == 1) fill(h, top, before + 1);
        else fill(h, c, all - before);
        break;
    }
    case 'K': {
        int m = na ? a[0] : 0; COORD s0 = { 0, c.Y };
        if (m == 2) fill(h, s0, (DWORD)i.dwSize.X);
        else if (m == 1) fill(h, s0, (DWORD)c.X + 1);
        else fill(h, c, (DWORD)(i.dwSize.X - c.X));
        break;
    }
    case 'm':
        if (!na) na = 1;
        for (int k = 0; k < na; k++) {
            int v = a[k];
            if (v == 0) { a_bold = a_dim = a_rev = 0; a_fg = a_bg = -1; }
            else if (v == 1) a_bold = 1;
            else if (v == 2) a_dim = 1;
            else if (v == 22) a_bold = a_dim = 0;
            else if (v == 7) a_rev = 1;
            else if (v == 27) a_rev = 0;
            else if (v >= 30 && v <= 37) a_fg = A2W[v - 30];
            else if (v == 39) a_fg = -1;
            else if (v >= 40 && v <= 47) a_bg = A2W[v - 40];
            else if (v == 49) a_bg = -1;
            else if (v >= 90 && v <= 97) a_fg = A2W[v - 90] | 8;
            else if (v >= 100 && v <= 107) a_bg = A2W[v - 100] | 8;
            else if (v == 38 || v == 48) { k += k + 1 < na && a[k + 1] == 5 ? 2 : 4; }   /* 256 色 / 真彩: 不认, 跳过参数 */
        }
        SetConsoleTextAttribute(h, cur_attr());
        break;
    case 'h': case 'l':
        if (!priv) break;
        for (int k = 0; k < na; k++) {
            if (a[k] == 25) { CONSOLE_CURSOR_INFO ci; if (GetConsoleCursorInfo(h, &ci)) { ci.bVisible = f == 'h'; SetConsoleCursorInfo(h, &ci); } }
            else if (a[k] == 1049 || a[k] == 47 || a[k] == 1047) { alt_screen(base, f == 'h'); SetConsoleTextAttribute(tgt(base), cur_attr()); }
        }
        break;
    }
}

static void con_write(void *st, void *con, const char *s, size_t n)
{
    ast_t *a = st; HANDLE h = con;
    if (!have_def) { CONSOLE_SCREEN_BUFFER_INFO i; def_attr = GetConsoleScreenBufferInfo(h, &i) ? i.wAttributes : 7; have_def = 1; }
    size_t t0 = 0;                                    /* 一段连续文字的开头 */
    for (size_t k = 0; k < n; k++) {
        unsigned char c = (unsigned char)s[k];
        if (a->st == 0) {
            if (c != 27) continue;
            if (k > t0) wtext(h, a, s + t0, k - t0);
            a->st = 1; continue;
        }
        if (a->st == 1) {
            a->st = c == '[' ? 2 : c == ']' ? 3 : (c == '(' || c == ')') ? 5 : 0; a->np = 0;
            if (!a->st) t0 = k + 1;
            continue;
        }
        if (a->st == 5) { a->st = 0; t0 = k + 1; continue; }
        if (a->st == 3 || a->st == 4) {                   /* OSC: 到 BEL 或 ESC \ 为止, 整段吞掉 */
            if (c == 7 || (a->st == 4 && c == '\\')) { a->st = 0; t0 = k + 1; }
            else a->st = c == 27 ? 4 : 3;
            continue;
        }
        if (c >= 0x40 && c <= 0x7E) { a->par[a->np] = 0; csi(h, a->par, (char)c); a->st = 0; t0 = k + 1; }
        else if (a->np < (int)sizeof a->par - 1) a->par[a->np++] = (char)c;
    }
    if (a->st == 0 && n > t0) wtext(h, a, s + t0, n - t0);
}

/* 按键: KEY_EVENT → 终端字节; 字符按 UTF-8, 方向键等翻成 ESC [ x */
static int key_read(void *in, char *b, int cap)
{
    INPUT_RECORD r[32]; DWORD n; int o = 0;
    static WCHAR hi;                                  /* 代理对的前半 */
    if (!ReadConsoleInputW(in, r, 32, &n)) return -1;
    for (DWORD k = 0; k < n && o < cap - 16; k++) {
        if (r[k].EventType != KEY_EVENT || !r[k].Event.KeyEvent.bKeyDown) continue;
        KEY_EVENT_RECORD *e = &r[k].Event.KeyEvent;
        WCHAR ch = e->uChar.UnicodeChar;
        for (int rep = e->wRepeatCount ? e->wRepeatCount : 1; rep > 0 && o < cap - 16; rep--) {
            if (ch) {
                if (ch >= 0xD800 && ch <= 0xDBFF) { hi = ch; continue; }
                WCHAR pair[2]; int pn = 0;
                if (ch >= 0xDC00 && ch <= 0xDFFF && hi) { pair[pn++] = hi; hi = 0; }
                pair[pn++] = ch;
                o += WideCharToMultiByte(CP_UTF8, 0, pair, pn, b + o, cap - o, NULL, NULL);
                continue;
            }
            const char *q = NULL;
            switch (e->wVirtualKeyCode) {
            case VK_UP: q = "\x1b[A"; break;   case VK_DOWN: q = "\x1b[B"; break;
            case VK_RIGHT: q = "\x1b[C"; break; case VK_LEFT: q = "\x1b[D"; break;
            case VK_HOME: q = "\x1b[H"; break;  case VK_END: q = "\x1b[F"; break;
            case VK_PRIOR: q = "\x1b[5~"; break; case VK_NEXT: q = "\x1b[6~"; break;
            case VK_DELETE: q = "\x1b[3~"; break; case VK_INSERT: q = "\x1b[2~"; break;
            }
            if (q) { size_t l = strlen(q); memcpy(b + o, q, l); o += (int)l; }
        }
    }
    return o;
}

const winmod_t WINMOD = { "win7", line_edit, sizeof(lst_t), con_write, sizeof(ast_t), key_read };
