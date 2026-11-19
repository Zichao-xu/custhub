/* Windows 平台模块内部: plat_win.c(共用部分) 和版本模块之间的接口
 *   Win10 1809 起: plat_win10.c(什么都不补)
 *   Win7 / 8 / 8.1: plat_win7.c(没有 ConPTY 时的交互 shell: 管道 + 行编辑回显; 控制台不认 ANSI: 输出、按键翻译)
 * 编译时二选一链进去(build.sh), 主线代码里不写 #if */
#ifndef PLAT_WIN_H
#define PLAT_WIN_H
#include <stddef.h>

typedef struct {
    const char *name;
    /* 没有 ConPTY 时的交互 shell: 对方的按键 in[0..n) → 交给子进程的 to_child[*nc]、回显给对方的 echo[*ne]
     *   to_child 至少 2n+4096、echo 至少 4n+4096; st 是 line_state_size 字节、开头全 0 的会话状态; NULL = 不支持(要 ConPTY) */
    void (*line_edit)(void *st, const char *in, int n, char *to_child, int *nc, char *echo, int *ne);
    size_t line_state_size;
    /* 控制台不认 ANSI 时(Win7): 程序输出(UTF-8, 带 ANSI 控制码)翻译成控制台调用写到 con(控制台输出句柄); st 是 con_state_size 字节、开头全 0
     *   NULL = 控制台自己认 ANSI(Win10) */
    void (*con_write)(void *st, void *con, const char *s, size_t n);
    size_t con_state_size;
    /* 同上: 原始模式下读一批按键(控制台输入句柄 in), 翻成终端字节(UTF-8, 方向键等 ESC [ x); 返回字节数, 0 = 这批没有按键, -1 = 出错 */
    int (*key_read)(void *in, char *b, int cap);
} winmod_t;

extern const winmod_t WINMOD;
#endif
