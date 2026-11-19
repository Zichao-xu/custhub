/* Windows 平台模块内部: plat_win.c(共用部分) 和版本模块之间的接口
 *   Win10 1809 起: plat_win10.c(什么都不补)
 *   Win7 / 8 / 8.1: plat_win7.c(没有 ConPTY 时的交互 shell: 管道 + 行编辑回显)
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
} winmod_t;

extern const winmod_t WINMOD;
#endif
