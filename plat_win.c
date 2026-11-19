/* 平台模块: Windows(Win10 1809 起, design-v3 §0)。只有这里和 plat_posix.c 能 include 系统头文件 */
#include "plat.h"
#include "plat_win.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RtlGenRandom SystemFunction036
BOOLEAN NTAPI RtlGenRandom(PVOID buf, ULONG len);   /* advapi32 */

static int would(int e) { return e == WSAEWOULDBLOCK || e == WSAEINTR; }

int p_init(void) { WSADATA w; return WSAStartup(MAKEWORD(2, 2), &w); }

int p_poll(pfd_t *p, int n, int ms)
{
    static WSAPOLLFD q[1024];
    if (n > (int)(sizeof q / sizeof q[0])) n = (int)(sizeof q / sizeof q[0]);
    for (int i = 0; i < n; i++) {
        q[i].fd = (SOCKET)p[i].fd; q[i].revents = 0;
        q[i].events = (short)((p[i].ev & P_IN ? POLLRDNORM : 0) | (p[i].ev & P_OUT ? POLLWRNORM : 0));
    }
    int r = WSAPoll(q, (ULONG)n, ms);
    if (r < 0) return would(WSAGetLastError()) ? 0 : -1;
    for (int i = 0; i < n; i++)
        p[i].rev = (short)((q[i].revents & POLLRDNORM ? P_IN : 0) | (q[i].revents & POLLWRNORM ? P_OUT : 0) |
                           (q[i].revents & (POLLHUP | POLLERR | POLLNVAL) ? P_HUP : 0));
    return r;
}

long p_recv(int fd, void *b, size_t n)
{
    int r = recv((SOCKET)fd, (char *)b, (int)n, 0);
    if (r >= 0) return r;
    return would(WSAGetLastError()) ? P_AGAIN : P_FAIL;
}

long p_send(int fd, const void *b, size_t n)
{
    int r = send((SOCKET)fd, (const char *)b, (int)n, 0);
    if (r >= 0) return r;
    return would(WSAGetLastError()) ? P_AGAIN : P_FAIL;
}

void p_close(int fd) { closesocket((SOCKET)fd); }
void p_shut_wr(int fd) { shutdown((SOCKET)fd, SD_SEND); }

void p_nb(int fd)
{
    u_long one = 1; BOOL nd = TRUE;
    SetHandleInformation((HANDLE)(uintptr_t)fd, HANDLE_FLAG_INHERIT, 0);
    setsockopt((SOCKET)fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&nd, sizeof nd);
    ioctlsocket((SOCKET)fd, FIONBIO, &one);
}

void p_block(int fd) { u_long z = 0; ioctlsocket((SOCKET)fd, FIONBIO, &z); }
int p_lasterr(void) { return WSAGetLastError(); }

const char *p_strerr(int e)
{
    static char b[64];
    switch (e) {
    case WSAECONNREFUSED: return "拒绝连接";
    case WSAECONNRESET:   return "连接被重置";
    case WSAETIMEDOUT:    return "超时";
    case WSAEHOSTUNREACH: case WSAENETUNREACH: return "网络不可达";
    }
    snprintf(b, sizeof b, "WSA 错误 %d", e);
    return b;
}

int p_dial(const char *host, int port, int nb, char *why, size_t wcap)
{
    struct addrinfo hints, *ai = NULL;
    char ps[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &ai) || !ai) { snprintf(why, wcap, "解析不了 %s", host); return -1; }
    SOCKET s = socket(ai->ai_family, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { snprintf(why, wcap, "%s", p_strerr(WSAGetLastError())); freeaddrinfo(ai); return -1; }
    if (nb) p_nb((int)s);
    int r = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
    freeaddrinfo(ai);
    if (r < 0) {
        int e = WSAGetLastError();
        if (!(nb && (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS))) { snprintf(why, wcap, "%s", p_strerr(e)); closesocket(s); return -1; }
    }
    return (int)s;
}

int p_dial_result(int fd)
{
    int err = 0, l = sizeof err;
    if (getsockopt((SOCKET)fd, SOL_SOCKET, SO_ERROR, (char *)&err, &l)) return WSAGetLastError();
    return err;
}

int p_listen(const char *host, int port)
{
    struct addrinfo hints, *ai = NULL;
    char ps[8]; int one = 1;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE;
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &ai) || !ai) return -1;
    SOCKET s = socket(ai->ai_family, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { freeaddrinfo(ai); return -1; }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    if (bind(s, ai->ai_addr, (int)ai->ai_addrlen) || listen(s, 64)) { freeaddrinfo(ai); closesocket(s); return -1; }
    freeaddrinfo(ai);
    p_nb((int)s);
    return (int)s;
}

int p_accept(int lfd, char *peer, size_t pcap)
{
    struct sockaddr_storage sa; int l = sizeof sa;
    SOCKET s = accept((SOCKET)lfd, (struct sockaddr *)&sa, &l);
    if (s == INVALID_SOCKET) return -1;
    char h[64] = "?"; int port = 0;
    if (sa.ss_family == AF_INET) { struct sockaddr_in *s4 = (void *)&sa; inet_ntop(AF_INET, &s4->sin_addr, h, sizeof h); port = ntohs(s4->sin_port); }
    else if (sa.ss_family == AF_INET6) { struct sockaddr_in6 *s6 = (void *)&sa; inet_ntop(AF_INET6, &s6->sin6_addr, h, sizeof h); port = ntohs(s6->sin6_port); }
    if (peer) snprintf(peer, pcap, "%s:%d", h, port);
    p_nb((int)s);
    return (int)s;
}

void p_open_firewall(int port) { (void)port; }

int64_t now_ms(void) { return (int64_t)GetTickCount64(); }

int64_t wall_ms(void)
{
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 10000;   /* 1601 起的毫秒 */
    return (int64_t)(t - 11644473600000ULL);
}

void rnd(uint8_t *out, size_t n)
{
    if (!RtlGenRandom(out, (ULONG)n)) { fprintf(stderr, "取不到随机数\n"); abort(); }
}

int p_replace(const char *from, const char *to) { return MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING) ? 0 : -1; }

static DWORD WINAPI pump_in(LPVOID arg)          /* 标准输入 → socket; 读完半关 */
{
    SOCKET s = (SOCKET)(intptr_t)arg; char b[16384]; DWORD r;
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    while (ReadFile(in, b, sizeof b, &r, NULL) && r > 0)
        for (DWORD o = 0; o < r;) { int w = send(s, b + o, (int)(r - o), 0); if (w <= 0) return 0; o += (DWORD)w; }
    shutdown(s, SD_SEND);
    return 0;
}

int p_pump_stdio(int fd)
{
    char b[16384];
    CreateThread(NULL, 0, pump_in, (LPVOID)(intptr_t)fd, 0, NULL);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    for (;;) {
        int r = recv((SOCKET)fd, b, sizeof b, 0);
        if (r <= 0) return 0;
        DWORD w; if (!WriteFile(out, b, (DWORD)r, &w, NULL)) return 1;
    }
}

long p_agent_call(const uint8_t *req, size_t n, uint8_t *resp, size_t cap, char *why, size_t wcap)
{
    /* Windows 自带 OpenSSH 的 agent 服务: 命名管道 */
    HANDLE h = CreateFileA("\\\\.\\pipe\\openssh-ssh-agent", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { snprintf(why, wcap, "连不上 ssh-agent(Windows 的 OpenSSH Authentication Agent 服务没开?)"); return -1; }
    DWORD w, r; uint8_t hd[4]; size_t got = 0;
    if (!WriteFile(h, req, (DWORD)n, &w, NULL) || w != n) { snprintf(why, wcap, "写 ssh-agent 失败"); CloseHandle(h); return -1; }
    while (got < 4 && ReadFile(h, hd + got, (DWORD)(4 - got), &r, NULL) && r > 0) got += r;
    size_t len = got == 4 ? (size_t)hd[0] << 24 | (size_t)hd[1] << 16 | (size_t)hd[2] << 8 | hd[3] : 0;
    if (got != 4 || len == 0 || len > cap) { snprintf(why, wcap, "ssh-agent 回答不对"); CloseHandle(h); return -1; }
    for (got = 0; got < len;) { if (!ReadFile(h, resp + got, (DWORD)(len - got), &r, NULL) || !r) { snprintf(why, wcap, "ssh-agent 回答不完整"); CloseHandle(h); return -1; } got += r; }
    CloseHandle(h);
    return (long)len;
}

/* ---------- 伪终端(design-v3 §0 第 6 条: Win10 1809 起有 ConPTY) ----------
 * 交互: ConPTY(输出是 VT 序列, 和 POSIX 伪终端对等); 跑命令: 普通管道(输出逐字节原样, 输入能真正"到头")
 * 管道和控制台放不进 WSAPoll: 每个会话一对 socket, 后台线程把 socket ↔ 管道桥起来; 核心只看到 socket
 * 进程放进作业对象, 关会话时整棵进程树一起收掉 */
int p_pair(int fd[2])
{
    int l = p_listen("127.0.0.1", 0);
    if (l < 0) return -1;
    struct sockaddr_in a; int al = sizeof a;
    if (getsockname((SOCKET)l, (struct sockaddr *)&a, &al)) { closesocket((SOCKET)l); return -1; }
    char why[64];
    int c = p_dial("127.0.0.1", ntohs(a.sin_port), 0, why, sizeof why);
    if (c < 0) { closesocket((SOCKET)l); return -1; }
    p_block(l);
    SOCKET s = accept((SOCKET)l, NULL, NULL);
    closesocket((SOCKET)l);
    if (s == INVALID_SOCKET) { closesocket((SOCKET)c); return -1; }
    p_nb(c); p_nb((int)s);
    fd[0] = c; fd[1] = (int)s;
    return 0;
}

typedef void *hpcon_t;
typedef HRESULT (WINAPI *create_pc_t)(COORD, HANDLE, HANDLE, DWORD, hpcon_t *);
typedef HRESULT (WINAPI *resize_pc_t)(hpcon_t, COORD);
typedef void (WINAPI *close_pc_t)(hpcon_t);
static create_pc_t pc_create; static resize_pc_t pc_resize; static close_pc_t pc_close;
#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

typedef struct {
    volatile LONG refs;
    HANDLE proc, job, in_w, out_r;
    hpcon_t hpc;
    SOCKET br;                    /* 桥这一头(阻塞, 线程用) */
    int core, conpty, legacy;     /* core: 交给核心的那一头; legacy: 没有 ConPTY 的交互 shell(版本模块做行编辑) */
} wpty_t;
#define MAXPTY 32
static wpty_t *WP[MAXPTY];

static void wp_release(wpty_t *w)
{
    if (InterlockedDecrement(&w->refs)) return;
    if (w->in_w) CloseHandle(w->in_w);
    if (w->out_r) CloseHandle(w->out_r);
    if (w->proc) CloseHandle(w->proc);
    if (w->job) CloseHandle(w->job);
    closesocket(w->br);
    free(w);
}

static DWORD WINAPI t_in(LPVOID a)          /* socket → 子进程输入 */
{
    wpty_t *w = a; char b[16384];
    void *ls = NULL; char *tc = NULL, *ec = NULL;          /* 每个会话一份(多个 shell 同时开) */
    if (w->legacy && (!(ls = calloc(1, WINMOD.line_state_size)) || !(tc = malloc(16384 * 2 + 4096)) || !(ec = malloc(16384 * 4 + 4096)))) goto out;
    for (;;) {
        int r = recv(w->br, b, sizeof b, 0);
        if (r <= 0) break;
        DWORD k; const char *src = b; int n = r;
        if (w->legacy) {                                 /* 行编辑: 回显给对方, 整行交给子进程 */
            int nc = 0, ne = 0;
            WINMOD.line_edit(ls, b, r, tc, &nc, ec, &ne);
            for (int o = 0; o < ne;) { int q = send(w->br, ec + o, ne - o, 0); if (q <= 0) goto out; o += q; }
            src = tc; n = nc;
        }
        for (int o = 0; o < n; o += (int)k) if (!WriteFile(w->in_w, src + o, (DWORD)(n - o), &k, NULL) || !k) goto out;
    }
out:
    free(ls); free(tc); free(ec);
    if (!w->conpty) { HANDLE h = w->in_w; w->in_w = NULL; CloseHandle(h); }   /* 跑命令: 关掉输入 = 真正的"到头" */
    wp_release(w);
    return 0;
}

static DWORD WINAPI t_out(LPVOID a)         /* 子进程输出 → socket; 读到头就半关, 核心据此知道输出完了 */
{
    wpty_t *w = a; char b[16384]; DWORD r;
    while (ReadFile(w->out_r, b, sizeof b, &r, NULL) && r)
        for (DWORD o = 0; o < r;) { int k = send(w->br, b + o, (int)(r - o), 0); if (k <= 0) goto out; o += (DWORD)k; }
out:
    shutdown(w->br, SD_SEND);
    wp_release(w);
    return 0;
}

static DWORD WINAPI t_wait(LPVOID a)        /* ConPTY: 进程退出后要关掉伪控制台, 输出管道才会到头 */
{
    wpty_t *w = a;
    WaitForSingleObject(w->proc, INFINITE);
    pc_close(w->hpc);
    wp_release(w);
    return 0;
}

/* 子进程会继承"忽略 Ctrl-C"标记: 守护进程若是从 ssh 会话、服务里起来的, 往往带着它, ConPTY 里的 Ctrl-C 就打不断命令
 * 起交互会话前清掉本进程的这个标记, 改用一个吞掉 Ctrl-C 的处理函数: 守护进程自己照样不被打断, 子进程不再继承"忽略" */
static BOOL WINAPI swallow_ctrl(DWORD t) { (void)t; return TRUE; }

static WCHAR *wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    WCHAR *w = n > 0 ? malloc((size_t)n * sizeof(WCHAR)) : NULL;
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

int p_pty_open(const char *cmd, int rows, int cols, const char *term, int *fd, char *why, size_t wcap)
{
    (void)term;
    int h = -1;
    for (int i = 0; i < MAXPTY && h < 0; i++) if (!WP[i]) h = i;
    if (h < 0) { snprintf(why, wcap, "shell 太多了"); return -1; }
    if (!cmd && !pc_create) {
        HMODULE k = GetModuleHandleA("kernel32.dll");
        pc_create = (create_pc_t)(void *)GetProcAddress(k, "CreatePseudoConsole");
        pc_resize = (resize_pc_t)(void *)GetProcAddress(k, "ResizePseudoConsole");
        pc_close = (close_pc_t)(void *)GetProcAddress(k, "ClosePseudoConsole");
    }
    int legacy = !cmd && (!pc_create || !pc_resize || !pc_close);
    if (legacy && !WINMOD.line_edit) { snprintf(why, wcap, "这台 Windows 没有 ConPTY(要 Win10 1809 以上; Win7 用 win7 版)"); return -1; }

    int sp[2];
    if (p_pair(sp)) { snprintf(why, wcap, "开不了 shell 通道"); return -1; }
    wpty_t *w = calloc(1, sizeof *w);
    if (!w) { closesocket((SOCKET)sp[0]); closesocket((SOCKET)sp[1]); snprintf(why, wcap, "内存不足"); return -1; }
    w->core = sp[0]; w->br = (SOCKET)sp[1]; w->conpty = !cmd && !legacy; w->legacy = legacy;
    p_block(sp[1]);

    /* 命令行: 交互 = PowerShell(没有就 cmd); 跑命令 = cmd /c, 输出 UTF-8 */
    char sysd[MAX_PATH] = "C:\\Windows", ps[MAX_PATH + 64], line[32768];
    GetEnvironmentVariableA("SystemRoot", sysd, sizeof sysd);
    snprintf(ps, sizeof ps, "%s\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", sysd);
    if (legacy)              /* 没有 ConPTY: 管道接一个交互 cmd(代码页先切 UTF-8, 同跑命令) */
        snprintf(line, sizeof line, "%s\\System32\\cmd.exe /d /s /c \"chcp 65001 >nul && %s\\System32\\cmd.exe /d\"", sysd, sysd);
    else if (!cmd) {
        if (GetFileAttributesA(ps) != INVALID_FILE_ATTRIBUTES) snprintf(line, sizeof line, "\"%s\" -NoLogo", ps);
        else snprintf(line, sizeof line, "%s\\System32\\cmd.exe", sysd);
    } else   /* 先切 UTF-8 代码页, 再起一个新的 cmd 跑命令(cmd 启动时就记下代码页, 同一个 cmd 里切了对它自己不算数) */
        snprintf(line, sizeof line, "%s\\System32\\cmd.exe /d /s /c \"chcp 65001 >nul && %s\\System32\\cmd.exe /d /s /c \"%s\"\"", sysd, sysd, cmd);
    WCHAR *wl = wide(line);

    HANDLE in_r = NULL, out_w = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    STARTUPINFOEXW si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); memset(&pi, 0, sizeof pi);
    si.StartupInfo.cb = sizeof si;
    LPPROC_THREAD_ATTRIBUTE_LIST al = NULL;
    BOOL ok = FALSE; DWORD flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    const char *fail = "开不了管道";
    int piped = cmd || legacy;
    if (!CreatePipe(&in_r, &w->in_w, piped ? &sa : NULL, 0) || !CreatePipe(&w->out_r, &out_w, piped ? &sa : NULL, 0)) goto bad;
    if (piped) {
        SetHandleInformation(w->in_w, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(w->out_r, HANDLE_FLAG_INHERIT, 0);
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.StartupInfo.hStdInput = in_r; si.StartupInfo.hStdOutput = out_w; si.StartupInfo.hStdError = out_w;
        si.StartupInfo.wShowWindow = SW_HIDE;
        flags |= CREATE_NEW_CONSOLE;                      /* 给一个隐藏的控制台: 没有控制台时 chcp 65001 不生效, 输出会是系统代码页 */
        fail = "起不了进程";
        ok = CreateProcessW(NULL, wl, NULL, NULL, TRUE, flags, NULL, NULL, &si.StartupInfo, &pi);
    } else {
        COORD sz = { (SHORT)cols, (SHORT)rows };
        static int ctrl_fixed;
        if (!ctrl_fixed) { SetConsoleCtrlHandler(NULL, FALSE); SetConsoleCtrlHandler(swallow_ctrl, TRUE); ctrl_fixed = 1; }
        fail = "开不了伪控制台";
        if (FAILED(pc_create(sz, in_r, out_w, 0, &w->hpc))) goto bad;
        SIZE_T n = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &n);
        al = malloc(n);
        if (!al || !InitializeProcThreadAttributeList(al, 1, 0, &n) ||
            !UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, w->hpc, sizeof w->hpc, NULL, NULL)) goto bad;
        si.lpAttributeList = al;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;  /* 不继承守护进程自己的标准输入输出, 用伪控制台 */
        flags |= EXTENDED_STARTUPINFO_PRESENT;
        fail = "起不了进程";
        ok = CreateProcessW(NULL, wl, NULL, NULL, FALSE, flags, NULL, NULL, &si.StartupInfo, &pi);
    }
    if (!ok) goto bad;
    CloseHandle(in_r); CloseHandle(out_w); in_r = out_w = NULL;
    if (al) { DeleteProcThreadAttributeList(al); free(al); al = NULL; }
    free(wl); wl = NULL;
    w->proc = pi.hProcess;
    w->job = CreateJobObjectW(NULL, NULL);
    if (w->job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION li; memset(&li, 0, sizeof li);
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(w->job, JobObjectExtendedLimitInformation, &li, sizeof li);
        AssignProcessToJobObject(w->job, w->proc);
    }
    ResumeThread(pi.hThread); CloseHandle(pi.hThread);
    w->refs = 1 + 2 + (w->conpty ? 1 : 0);           /* 句柄表 + 两个桥线程 (+ 等退出的线程) */
    HANDLE t;
    if ((t = CreateThread(NULL, 0, t_in, w, 0, NULL))) CloseHandle(t); else wp_release(w);
    if ((t = CreateThread(NULL, 0, t_out, w, 0, NULL))) CloseHandle(t); else wp_release(w);
    if (w->conpty) { if ((t = CreateThread(NULL, 0, t_wait, w, 0, NULL))) CloseHandle(t); else wp_release(w); }
    WP[h] = w;
    *fd = w->core;
    return h;
bad:
    snprintf(why, wcap, "%s(错误 %lu)", fail, (unsigned long)GetLastError());
    if (in_r) CloseHandle(in_r);
    if (out_w) CloseHandle(out_w);
    if (w->in_w) CloseHandle(w->in_w);
    if (w->out_r) CloseHandle(w->out_r);
    if (w->hpc) pc_close(w->hpc);
    if (al) { DeleteProcThreadAttributeList(al); free(al); }
    free(wl);
    closesocket((SOCKET)w->core); closesocket(w->br); free(w);
    return -1;
}

void p_pty_resize(int h, int rows, int cols)
{
    if (h < 0 || h >= MAXPTY || !WP[h] || !WP[h]->conpty) return;
    COORD sz = { (SHORT)cols, (SHORT)rows };
    pc_resize(WP[h]->hpc, sz);
}

int p_pty_exit(int h, int *code)
{
    if (h < 0 || h >= MAXPTY || !WP[h]) return 1;
    if (WaitForSingleObject(WP[h]->proc, 0) != WAIT_OBJECT_0) return 0;
    DWORD c = 255; GetExitCodeProcess(WP[h]->proc, &c);
    *code = (int)c;
    return 1;
}

void p_pty_eof(int h)
{
    if (h < 0 || h >= MAXPTY || !WP[h]) return;
    if (!WP[h]->conpty) shutdown((SOCKET)WP[h]->core, SD_SEND);   /* 桥线程读到头后关掉子进程输入(写过的都先送到) */
}

void p_pty_close(int h)
{
    if (h < 0 || h >= MAXPTY || !WP[h]) return;
    wpty_t *w = WP[h]; WP[h] = NULL;
    if (w->job) TerminateJobObject(w->job, 1); else TerminateProcess(w->proc, 1);
    closesocket((SOCKET)w->core);
    wp_release(w);
}

/* ---------- 本地终端(工程师在 Windows 上用 mesh sh) ---------- */
#ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
#define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef DISABLE_NEWLINE_AUTO_RETURN
#define DISABLE_NEWLINE_AUTO_RETURN 0x0008
#endif
static DWORD in_mode, out_mode; static UINT out_cp; static int raw_on, last_r, last_c, vt_ok = 1;
int p_tty_ansi(void) { return vt_ok; }

int p_tty_raw(int on)
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE), out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD m;
    if (!GetConsoleMode(in, &m)) return 0;
    if (on && !raw_on) {
        in_mode = m; GetConsoleMode(out, &out_mode); out_cp = GetConsoleOutputCP();
        DWORD raw = m & ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        if (!SetConsoleMode(in, raw | ENABLE_VIRTUAL_TERMINAL_INPUT)) SetConsoleMode(in, raw);   /* Win7 控制台不认 VT 标志: 不带它再来 */
        vt_ok = SetConsoleMode(out, out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN) != 0;
        SetConsoleOutputCP(CP_UTF8);
        raw_on = 1;
        p_tty_size(&last_r, &last_c);
    } else if (!on && raw_on) { SetConsoleMode(in, in_mode); SetConsoleMode(out, out_mode); SetConsoleOutputCP(out_cp); raw_on = 0; }
    return 1;
}

int p_tty_size(int *rows, int *cols)
{
    CONSOLE_SCREEN_BUFFER_INFO i;
    if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &i)) return -1;
    *rows = i.srWindow.Bottom - i.srWindow.Top + 1; *cols = i.srWindow.Right - i.srWindow.Left + 1;
    return 0;
}

int p_tty_resized(void)
{
    int r, c;
    if (!raw_on || p_tty_size(&r, &c) || (r == last_r && c == last_c)) return 0;
    last_r = r; last_c = c;
    return 1;
}

static DWORD WINAPI t_stdin(LPVOID a)       /* 标准输入(控制台或管道) → socket */
{
    SOCKET s = (SOCKET)(intptr_t)a; char b[16384]; DWORD r;
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    while (ReadFile(in, b, sizeof b, &r, NULL) && r)
        for (DWORD o = 0; o < r;) { int k = send(s, b + o, (int)(r - o), 0); if (k <= 0) return 0; o += (DWORD)k; }
    shutdown(s, SD_SEND);
    return 0;
}

int p_stdin_fd(void)
{
    static int fd = -1;
    int sp[2];
    if (fd >= 0) return fd;
    if (p_pair(sp)) return -1;
    p_block(sp[1]);
    HANDLE t = CreateThread(NULL, 0, t_stdin, (LPVOID)(intptr_t)sp[1], 0, NULL);
    if (!t) { closesocket((SOCKET)sp[0]); closesocket((SOCKET)sp[1]); return -1; }
    CloseHandle(t);
    return fd = sp[0];
}

int p_stdout_write(const void *b, size_t n)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const char *p = b; DWORD w;
    while (n) { if (!WriteFile(out, p, (DWORD)n, &w, NULL) || !w) return -1; p += w; n -= w; }
    return 0;
}

char **p_args_utf8(int argc, char **argv)
{
    int wn = 0;
    LPWSTR *wa = CommandLineToArgvW(GetCommandLineW(), &wn);
    if (!wa || wn < argc) return argv;
    char **out = calloc((size_t)argc + 1, sizeof *out);
    if (!out) return argv;
    for (int i = 0; i < argc; i++) {
        LPWSTR w = wa[wn - argc + i];
        int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
        out[i] = n > 0 ? malloc((size_t)n) : NULL;
        if (!out[i]) return argv;
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out[i], n, NULL, NULL);
    }
    return out;
}

/* ---------- UDP ---------- */
int p_udp_open(void)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return -1;
    u_long one = 1; ioctlsocket(s, FIONBIO, &one);
    SetHandleInformation((HANDLE)(uintptr_t)s, HANDLE_FLAG_INHERIT, 0);
    return (int)s;
}

int p_udp_sendto(int fd, const char *host, int port, const void *b, size_t n)
{
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) return -1;
    return sendto((SOCKET)fd, (const char *)b, (int)n, 0, (struct sockaddr *)&a, sizeof a) == (int)n ? 0 : -1;
}

long p_udp_recv(int fd, void *b, size_t cap)
{
    int r = recvfrom((SOCKET)fd, (char *)b, (int)cap, 0, NULL, NULL);
    if (r >= 0) return r;
    return would(WSAGetLastError()) ? P_AGAIN : P_FAIL;
}

int p_local_ip(const char *peer_host, char *out, size_t cap)
{
    struct sockaddr_in a; int l = sizeof a;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return -1;
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons(9);
    if (inet_pton(AF_INET, peer_host, &a.sin_addr) != 1 || connect(s, (struct sockaddr *)&a, sizeof a) ||
        getsockname(s, (struct sockaddr *)&a, &l) || !inet_ntop(AF_INET, &a.sin_addr, out, cap)) { closesocket(s); return -1; }
    closesocket(s);
    return 0;
}

/* ---------- 自升级 ---------- */
int p_self_path(char *out, size_t cap)
{
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
    return n > 0 && n < cap ? 0 : -1;
}

static int cmdline_of(const char *const *argv, char *cl, size_t cap)   /* 按 CommandLineToArgvW 的规矩加引号 */
{
    size_t o = 0;
    for (int i = 0; argv[i]; i++) {
        const char *a = argv[i];
        if (o + strlen(a) * 2 + 4 >= cap) return -1;
        if (i) cl[o++] = ' ';
        cl[o++] = '"';
        for (const char *p = a; *p; p++) {
            size_t bs = 0;
            while (*p == '\\') { bs++; p++; }
            if (!*p) { while (bs--) { cl[o++] = '\\'; cl[o++] = '\\'; } break; }
            if (*p == '"') { while (bs--) { cl[o++] = '\\'; cl[o++] = '\\'; } cl[o++] = '\\'; cl[o++] = '"'; }
            else { while (bs--) cl[o++] = '\\'; cl[o++] = *p; }
        }
        cl[o++] = '"';
    }
    cl[o] = 0;
    return 0;
}

int p_run(const char *const *argv, char *out, size_t cap, int timeout_s)
{
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE rd, wr;
    char cl[8192];
    if (cmdline_of(argv, cl, sizeof cl) || !CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES; si.hStdOutput = wr; si.hStdError = wr; si.hStdInput = NULL;
    if (!CreateProcessA(NULL, cl, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { CloseHandle(rd); CloseHandle(wr); return -1; }
    CloseHandle(wr); CloseHandle(pi.hThread);
    size_t n = 0; int timed = 0;
    ULONGLONG end = GetTickCount64() + (ULONGLONG)timeout_s * 1000;
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL)) break;
        if (avail) {
            char tmp[4096]; DWORD k = 0;
            if (!ReadFile(rd, tmp, avail < sizeof tmp ? avail : sizeof tmp, &k, NULL) || !k) break;
            if (out && n + 1 < cap) { size_t c = k < cap - 1 - n ? k : cap - 1 - n; memcpy(out + n, tmp, c); n += c; }
            continue;
        }
        if (GetTickCount64() >= end) { timed = 1; break; }
        if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) { if (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail) continue; break; }
    }
    CloseHandle(rd);
    if (out) out[n] = 0;
    DWORD code = (DWORD)-1;
    if (timed) TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 5000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return timed ? -2 : (int)code;
}

void p_make_exec(const char *path) { (void)path; }

void p_exec_self(const char *exe, const char *const *argv)   /* 起新进程接班后退出; 退出码非 0, 服务管理器的"失败重启"再兜一层底 */
{
    (void)exe;
    char cl[8192];
    if (cmdline_of(argv, cl, sizeof cl)) return;
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    DWORD fl = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    if (!CreateProcessA(NULL, cl, NULL, NULL, FALSE, fl | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, &si, &pi) &&
        !CreateProcessA(NULL, cl, NULL, NULL, FALSE, fl, NULL, NULL, &si, &pi)) return;
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    ExitProcess(3);
}

/* 下载: WinHTTP(按需加载 winhttp.dll, 导入表里不多出 DLL), 后台线程 */
typedef void *HINET_;
typedef struct { DWORD dwStructSize; LPWSTR lpszScheme; DWORD dwSchemeLength; int nScheme; LPWSTR lpszHostName; DWORD dwHostNameLength;
                 WORD nPort; LPWSTR lpszUserName; DWORD dwUserNameLength; LPWSTR lpszPassword; DWORD dwPasswordLength;
                 LPWSTR lpszUrlPath; DWORD dwUrlPathLength; LPWSTR lpszExtraInfo; DWORD dwExtraInfoLength; } urlc_t;
static struct {
    HINET_ (WINAPI *open)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    BOOL (WINAPI *crack)(LPCWSTR, DWORD, DWORD, urlc_t *);
    HINET_ (WINAPI *connect)(HINET_, LPCWSTR, WORD, DWORD);
    HINET_ (WINAPI *req)(HINET_, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
    BOOL (WINAPI *send)(HINET_, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    BOOL (WINAPI *recv)(HINET_, LPVOID);
    BOOL (WINAPI *query)(HINET_, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
    BOOL (WINAPI *read)(HINET_, LPVOID, DWORD, LPDWORD);
    BOOL (WINAPI *close)(HINET_);
    BOOL (WINAPI *timeouts)(HINET_, int, int, int, int);
    BOOL (WINAPI *setopt)(HINET_, DWORD, LPVOID, DWORD);
} WH;

static int wh_load(void)
{
    static int st;
    if (st) return st > 0 ? 0 : -1;
    HMODULE m = LoadLibraryA("winhttp.dll");
    st = -1;
    if (!m) return -1;
#define L(f, n) if (!(*(FARPROC *)&WH.f = GetProcAddress(m, n))) return -1
    L(open, "WinHttpOpen"); L(crack, "WinHttpCrackUrl"); L(connect, "WinHttpConnect"); L(req, "WinHttpOpenRequest");
    L(send, "WinHttpSendRequest"); L(recv, "WinHttpReceiveResponse"); L(query, "WinHttpQueryHeaders");
    L(read, "WinHttpReadData"); L(close, "WinHttpCloseHandle"); L(timeouts, "WinHttpSetTimeouts");
#undef L
    *(FARPROC *)&WH.setopt = GetProcAddress(m, "WinHttpSetOption");   /* 可选 */
    st = 1;
    return 0;
}

#define MAXFETCH 8
typedef struct { volatile LONG state; WCHAR url[2048]; char out[MAX_PATH * 2]; } fetch_t;   /* state: 0 空 1 下载中 2 好 3 失败 */
static fetch_t *FT[MAXFETCH];

static DWORD WINAPI t_fetch(LPVOID a)
{
    fetch_t *f = a; int ok = 0;
    WCHAR host[256], path[2048];
    urlc_t u; memset(&u, 0, sizeof u); u.dwStructSize = sizeof u;
    u.lpszHostName = host; u.dwHostNameLength = 256; u.lpszUrlPath = path; u.dwUrlPathLength = 2048; u.dwSchemeLength = (DWORD)-1;
    HINET_ s = NULL, c = NULL, r = NULL;
    FILE *fp = NULL;
    if (!WH.crack(f->url, 0, 0, &u)) goto out;
    s = WH.open(L"custhub", 0 /* WINHTTP_ACCESS_TYPE_DEFAULT_PROXY */, NULL, NULL, 0);
    if (!s) goto out;
    WH.timeouts(s, 15000, 15000, 30000, 60000);
    if (WH.setopt) { DWORD pr = 0x80 | 0x200 | 0x800;      /* TLS 1.0 / 1.1 / 1.2: Win7 默认不开 1.2(GitHub 要 1.2); 系统不支持就照旧, 取不到包由网内节点兜底 */
                     WH.setopt(s, 84 /* WINHTTP_OPTION_SECURE_PROTOCOLS */, &pr, sizeof pr); }
    c = WH.connect(s, host, u.nPort, 0);
    if (!c) goto out;
    r = WH.req(c, L"GET", path, NULL, NULL, NULL, u.nScheme == 2 /* INTERNET_SCHEME_HTTPS */ ? 0x00800000 /* WINHTTP_FLAG_SECURE */ : 0);
    if (!r || !WH.send(r, NULL, 0, NULL, 0, 0, 0) || !WH.recv(r, NULL)) goto out;
    DWORD code = 0, cl = sizeof code;
    if (!WH.query(r, 19 | 0x20000000 /* STATUS_CODE | FLAG_NUMBER */, NULL, &code, &cl, NULL) || code != 200) goto out;
    fp = fopen(f->out, "wb");
    if (!fp) goto out;
    char b[16384]; DWORD k;
    for (;;) {
        if (!WH.read(r, b, sizeof b, &k)) goto out;
        if (!k) break;
        if (fwrite(b, 1, k, fp) != k) goto out;
    }
    ok = fclose(fp) == 0; fp = NULL;
out:
    if (fp) fclose(fp);
    if (!ok) DeleteFileA(f->out);
    if (r) WH.close(r);
    if (c) WH.close(c);
    if (s) WH.close(s);
    InterlockedExchange(&f->state, ok ? 2 : 3);
    return 0;
}

int p_fetch_start(const char *url, const char *out)
{
    if (wh_load()) return -1;
    int h = -1;
    for (int i = 0; i < MAXFETCH && h < 0; i++) if (!FT[i]) h = i;
    if (h < 0) return -1;
    fetch_t *f = calloc(1, sizeof *f);
    if (!f || !MultiByteToWideChar(CP_UTF8, 0, url, -1, f->url, 2048)) { free(f); return -1; }
    snprintf(f->out, sizeof f->out, "%s", out);
    f->state = 1;
    HANDLE t = CreateThread(NULL, 0, t_fetch, f, 0, NULL);
    if (!t) { free(f); return -1; }
    CloseHandle(t);
    FT[h] = f;
    return h;
}

int p_fetch_poll(int h)
{
    if (h < 0 || h >= MAXFETCH || !FT[h]) return -1;
    LONG s = FT[h]->state;
    if (s == 1) return 0;
    free(FT[h]); FT[h] = NULL;
    return s == 2 ? 1 : -1;
}

void p_fetch_kill(int h)                    /* 线程停不下来: 不再管它, 它下完自己收(内存泄一点) */
{
    if (h < 0 || h >= MAXFETCH || !FT[h]) return;
    FT[h] = NULL;
}

/* ---------- 部署: Windows 用计划任务(SYSTEM 身份、开机起、每 5 分钟拉一次、失败重启), 同 0.2 ---------- */
static int user_mode;
void p_set_user_mode(int on) { user_mode = on; }
int p_user_mode(void) { return user_mode; }
const char *p_user_dir(void)
{
    static char d[MAX_PATH + 32];
    char la[MAX_PATH] = "C:\\Users\\Public";
    GetEnvironmentVariableA("LOCALAPPDATA", la, sizeof la);
    snprintf(d, sizeof d, "%s\\custhub", la);
    return d;
}

const char *p_install_dir(void)
{
    static char d[MAX_PATH + 32];
    const char *e = getenv("CUSTHUB_HOME");
    if (e && *e) return e;
    if (user_mode) return p_user_dir();
    char pd[MAX_PATH] = "C:\\ProgramData";
    GetEnvironmentVariableA("ProgramData", pd, sizeof pd);
    snprintf(d, sizeof d, "%s\\custhub", pd);
    return d;
}

int p_is_admin(void)
{
    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
    PSID g; BOOL m = FALSE;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &g)) return 0;
    if (!CheckTokenMembership(NULL, g, &m)) m = FALSE;
    FreeSid(g);
    return m;
}

int p_mkdir(const char *path) { return CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS ? 0 : -1; }
void p_private_files(void) { }                    /* Windows 靠目录的访问控制(p_private_dir), 子项继承 */
int p_private_dir(const char *path)
{
    /* 不继承上层(ProgramData 默认 Users 能读), 只给 SYSTEM 和 Administrators 完全控制, 子目录和文件都继承 */
    PSECURITY_DESCRIPTOR sd = NULL; PACL dacl = NULL; BOOL present = FALSE, def = FALSE;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &sd, NULL)) return -1;
    int r = -1;
    if (GetSecurityDescriptorDacl(sd, &present, &dacl, &def) && present &&
        SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL) == ERROR_SUCCESS) r = 0;
    LocalFree(sd);
    return r;
}
void p_hostname(char *out, size_t cap) { DWORD n = (DWORD)cap; if (!GetComputerNameA(out, &n)) snprintf(out, cap, "win"); }
void p_sleep_ms(int ms) { Sleep((DWORD)ms); }
const char *p_service_kind(void) { const char *k = getenv("CUSTHUB_SVC_KIND"); return k && *k ? k : "task"; }

static int wdry(void) { return getenv("CUSTHUB_SVC_DRY") != NULL; }
static int run_w(const char *const *av) { if (wdry()) return 0; char o[512]; return p_run(av, o, sizeof o, 60); }

int p_service_install(const char *exe, const char *dir, char *why, size_t wcap)
{
    if (user_mode) { snprintf(why, wcap, "Windows 上不支持用户模式(--user): 用管理员 PowerShell 装成系统服务"); return -1; }
    static char xml[4096], xp[MAX_PATH * 2];
    int n = snprintf(xml, sizeof xml,
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
        "<RegistrationInfo><Description>custhub</Description></RegistrationInfo>\r\n"
        "<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger>\r\n"
        "<TimeTrigger><StartBoundary>2020-01-01T00:00:00</StartBoundary><Enabled>true</Enabled>"
        "<Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger></Triggers>\r\n"
        "<Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\r\n"
        "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        "<AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>"
        "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
        "<IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>"
        "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>"
        "<RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>5</Priority>"
        "<RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>\r\n"
        "<Actions Context=\"Author\"><Exec><Command>%s</Command><Arguments>run \"%s\"</Arguments></Exec></Actions>\r\n"
        "</Task>\r\n", exe, dir);
    if (n <= 0 || n >= (int)sizeof xml) { snprintf(why, wcap, "路径太长"); return -1; }
    static WCHAR w[4300];
    w[0] = 0xFEFF;                                       /* schtasks /xml 要 UTF-16 */
    int k = MultiByteToWideChar(CP_UTF8, 0, xml, n, w + 1, 4299);
    if (k <= 0) { snprintf(why, wcap, "编码失败"); return -1; }
    if (wdry()) { snprintf(xp, sizeof xp, "%s\\dry", dir); p_mkdir(xp); snprintf(xp, sizeof xp, "%s\\dry\\custhub.xml", dir); }
    else snprintf(xp, sizeof xp, "%s\\custhub-task.xml", dir);
    FILE *f = fopen(xp, "wb");
    if (!f || fwrite(w, 2, (size_t)k + 1, f) != (size_t)k + 1) { if (f) fclose(f); snprintf(why, wcap, "写不了 %s", xp); return -1; }
    fclose(f);
    const char *c[] = { "schtasks", "/create", "/tn", "custhub", "/xml", xp, "/f", NULL };
    const char *r[] = { "schtasks", "/run", "/tn", "custhub", NULL };
    if (run_w(c)) { snprintf(why, wcap, "schtasks /create 失败"); return -1; }
    if (!wdry()) { DeleteFileA(xp); if (run_w(r)) { snprintf(why, wcap, "schtasks /run 失败"); return -1; } return 0; }
    const char *av[] = { exe, "run", dir, NULL };         /* 演练: 不碰系统, 直接在后台起 */
    char cl[8192];
    if (cmdline_of(av, cl, sizeof cl)) return -1;
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    if (!CreateProcessA(NULL, cl, NULL, NULL, FALSE, DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, NULL, NULL, &si, &pi)) { snprintf(why, wcap, "起不来"); return -1; }
    snprintf(xp, sizeof xp, "%s\\dry\\pid", dir);
    f = fopen(xp, "w"); if (f) { fprintf(f, "%lu\n", (unsigned long)pi.dwProcessId); fclose(f); }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}

int p_service_remove(const char *dir, char *why, size_t wcap)
{
    (void)why; (void)wcap;
    if (wdry()) {
        char p[MAX_PATH * 2], t[32]; snprintf(p, sizeof p, "%s\\dry\\pid", dir);
        FILE *f = fopen(p, "r");
        if (f) {
            if (fgets(t, sizeof t, f)) { HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)atol(t)); if (h) { TerminateProcess(h, 1); CloseHandle(h); } }
            fclose(f);
        }
        return 0;
    }
    const char *e[] = { "schtasks", "/end", "/tn", "custhub", NULL }, *d[] = { "schtasks", "/delete", "/tn", "custhub", "/f", NULL };
    run_w(e); run_w(d);
    return 0;
}

/* 命令加进 PATH: 把 exe 所在目录加进系统 PATH(用户模式: 当前用户的 PATH), 广播一下让新开的终端看得到
 * 节点目录只给 SYSTEM / Administrators, 所以要在"以管理员身份运行"的终端里用(同 Linux 上 sudo)。演练模式不碰注册表 */
static int path_has(const WCHAR *path, const WCHAR *d, size_t *at, size_t *len)
{
    size_t dl = wcslen(d);
    for (const WCHAR *p = path; *p; ) {
        const WCHAR *e = wcschr(p, L';'); size_t k = e ? (size_t)(e - p) : wcslen(p);
        size_t kk = k; while (kk && p[kk - 1] == L'\\') kk--;
        if (kk == dl && !_wcsnicmp(p, d, dl)) { *at = (size_t)(p - path); *len = k; return 1; }
        p += k; if (*p) p++;
    }
    return 0;
}

int p_path_link(const char *exe, int on, char *how, size_t cap)
{
    how[0] = 0;
    if (wdry()) return 0;
    char dir[MAX_PATH + 32]; snprintf(dir, sizeof dir, "%s", exe);
    char *sl = strrchr(dir, '\\'); if (!sl) { snprintf(how, cap, "认不出 %s 所在目录", exe); return -1; }
    *sl = 0;
    WCHAR *wd = wide(dir); if (!wd) return -1;
    HKEY root = user_mode ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
    const WCHAR *sub = user_mode ? L"Environment" : L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
    HKEY k; int r = -1;
    if (RegOpenKeyExW(root, sub, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &k)) { snprintf(how, cap, "打不开注册表里的环境变量"); free(wd); return -1; }
    static WCHAR cur[32768], nw[32768 + MAX_PATH + 4];
    DWORD type = REG_EXPAND_SZ, sz = sizeof cur - sizeof(WCHAR);
    LONG q = RegQueryValueExW(k, L"Path", NULL, &type, (BYTE *)cur, &sz);
    if (q == ERROR_FILE_NOT_FOUND) { cur[0] = 0; type = REG_EXPAND_SZ; }
    else if (q || (type != REG_SZ && type != REG_EXPAND_SZ)) { snprintf(how, cap, "读不了 PATH"); goto out; }
    else cur[sz / sizeof(WCHAR)] = 0;
    size_t at, len; int has = path_has(cur, wd, &at, &len), changed = 0;
    if (on && !has) {
        size_t cl = wcslen(cur);
        while (cl && cur[cl - 1] == L';') cur[--cl] = 0;
        _snwprintf(nw, sizeof nw / sizeof nw[0], L"%ls%ls%ls", cur, cl ? L";" : L"", wd); nw[sizeof nw / sizeof nw[0] - 1] = 0;
        changed = 1;
    } else if (!on && has) {
        size_t e = at + len; if (cur[e] == L';') e++; else if (at && cur[at - 1] == L';') at--;
        wcsncpy(nw, cur, at); nw[at] = 0; wcscat(nw, cur + e);
        changed = 1;
    }
    if (changed) {
        if (RegSetValueExW(k, L"Path", 0, type, (const BYTE *)nw, (DWORD)((wcslen(nw) + 1) * sizeof(WCHAR)))) { snprintf(how, cap, "写不了 PATH"); goto out; }
        DWORD_PTR res; SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 3000, &res);
    }
    snprintf(how, cap, on ? "%s 加进了 PATH(新开的管理员终端生效)" : "%s 移出了 PATH", dir);
    r = 0;
out:
    RegCloseKey(k); free(wd);
    return r;
}

/* ---------- 本机谁能用: 本地组 custhub ---------- */
static int grp_sid(char *out, size_t cap)              /* 组的 SID 字符串; 没有组 -1 */
{
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD sl = sizeof sid; WCHAR dom[256]; DWORD dl = 256; SID_NAME_USE use;
    if (!LookupAccountNameW(NULL, L"custhub", sid, &sl, dom, &dl, &use)) return -1;
    char *ss = NULL;
    if (!ConvertSidToStringSidA(sid, &ss)) return -1;
    snprintf(out, cap, "%s", ss); LocalFree(ss);
    return 0;
}

static int set_sddl(const char *path, const char *sddl)
{
    PSECURITY_DESCRIPTOR sd = NULL; PACL dacl = NULL; BOOL present = FALSE, def = FALSE;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &sd, NULL)) return -1;
    int r = -1;
    if (GetSecurityDescriptorDacl(sd, &present, &dacl, &def) && present &&
        SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL) == ERROR_SUCCESS) r = 0;
    LocalFree(sd);
    return r;
}

int p_group_setup(char *why, size_t wcap)
{
    char sid[200]; why[0] = 0;
    if (wdry() || !grp_sid(sid, sizeof sid)) return 0;
    const char *a[] = { "net", "localgroup", "custhub", "/add", NULL };
    char o[512]; p_run(a, o, sizeof o, 60);
    if (grp_sid(sid, sizeof sid)) { snprintf(why, wcap, "建不了本地组 custhub"); return -1; }
    return 0;
}

void p_group_share(const char *path, int dir)
{
    char sid[200], sddl[400];
    if (wdry() || dir || grp_sid(sid, sizeof sid)) return;   /* Windows 不用给目录"可进"(默认人人有跳过遍历检查的权限) */
    snprintf(sddl, sizeof sddl, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;%s)", sid);
    set_sddl(path, sddl);
}

int p_group_user(const char *user, int add, char *why, size_t wcap)
{
    why[0] = 0;
    if (wdry()) return 0;
    if (p_group_setup(why, wcap)) return -1;
    const char *a[] = { "net", "localgroup", "custhub", user, add ? "/add" : "/delete", NULL };
    char o[512];
    int r = p_run(a, o, sizeof o, 60);
    if (r) { for (char *c = o; *c; c++) if (*c == '\r' || *c == '\n') *c = ' '; snprintf(why, wcap, "net localgroup 失败(%d): %.200s", r, o); return -1; }
    return 0;
}

int p_group_list(char *out, size_t cap)
{
    out[0] = 0;
    char sid[200]; if (grp_sid(sid, sizeof sid)) return -1;
    const char *a[] = { "net", "localgroup", "custhub", NULL };
    static char o[8192];
    if (p_run(a, o, sizeof o, 60)) return -1;
    char *d = strstr(o, "-----"); if (!d) return 0;     /* 横线之后、最后一行("命令成功完成")之前是成员 */
    d = strchr(d, '\n'); if (!d) return 0;
    char *lines[64]; int nl = 0;
    for (char *l = strtok(d + 1, "\r\n"); l && nl < 64; l = strtok(NULL, "\r\n")) if (*l) lines[nl++] = l;
    size_t n = 0;
    for (int i = 0; i + 1 < nl && n < cap - 1; i++) n += (size_t)snprintf(out + n, cap - n, "%s%s", n ? " " : "", lines[i]);
    return 0;
}

int p_group_member(void)
{
    if (p_is_admin()) return 1;
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD sl = sizeof sid; WCHAR dom[256]; DWORD dl = 256; SID_NAME_USE use; BOOL m = FALSE;
    if (!LookupAccountNameW(NULL, L"custhub", sid, &sl, dom, &dl, &use)) return 0;
    if (!CheckTokenMembership(NULL, sid, &m)) m = FALSE;
    return m;
}

void p_public_dir(const char *path)
{
    if (wdry()) return;                                 /* SYSTEM / Administrators 完全控制, Users 只能读和运行(子项继承; 节点目录另设、不继承) */
    set_sddl(path, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)");
}

void p_username(char *out, size_t cap)
{
    char u[256]; DWORD n = sizeof u;
    if (!GetUserNameA(u, &n)) snprintf(u, sizeof u, "?");
    snprintf(out, cap, "%s", u);
}

const char *p_invoker(void)
{
    static char u[256]; DWORD n = sizeof u;
    if (!GetUserNameA(u, &n) || !u[0] || u[strlen(u) - 1] == '$' || !_stricmp(u, "SYSTEM")) return NULL;
    return u;
}

int p_elevate(int argc, char **argv) { (void)argc; (void)argv; return -1; }   /* 弹 UAC 的话输出在另一个窗口: 不做, 提示用管理员终端 */

/* ---------- 本机是什么机器 ---------- */
static void reg_str(HKEY root, const WCHAR *sub, const WCHAR *name, char *out, size_t cap)
{
    out[0] = 0; WCHAR w[256]; DWORD sz = sizeof w - sizeof(WCHAR), type = 0; HKEY k;
    if (RegOpenKeyExW(root, sub, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &k)) return;
    if (!RegQueryValueExW(k, name, NULL, &type, (BYTE *)w, &sz) && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        w[sz / sizeof(WCHAR)] = 0;
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
    }
    RegCloseKey(k);
}
void p_machine(char *os, size_t ocap, char *model, size_t mcap)
{
    const WCHAR *cv = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    char prod[128], disp[32], build[16];
    reg_str(HKEY_LOCAL_MACHINE, cv, L"ProductName", prod, sizeof prod);
    reg_str(HKEY_LOCAL_MACHINE, cv, L"DisplayVersion", disp, sizeof disp);
    reg_str(HKEY_LOCAL_MACHINE, cv, L"CurrentBuild", build, sizeof build);
    char *w10 = strstr(prod, "Windows 10");
    if (w10 && atoi(build) >= 22000) w10[9] = '1';     /* Win11 的 ProductName 还写着 Windows 10 */
    snprintf(os, ocap, "%s%s%s", prod, disp[0] ? " " : "", disp);
    char ven[96], mod[96];
    reg_str(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer", ven, sizeof ven);
    reg_str(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName", mod, sizeof mod);
    snprintf(model, mcap, "%s%s%s", ven, ven[0] && mod[0] ? " " : "", mod);
}

int p_rmtree(const char *path)
{
    DWORD a = GetFileAttributesA(path);
    if (a == INVALID_FILE_ATTRIBUTES) return 0;
    if (!(a & FILE_ATTRIBUTE_DIRECTORY)) {
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileA(path)) return 0;
        return MoveFileExA(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) ? 0 : -1;   /* 正在跑的程序: 重启后删 */
    }
    char q[MAX_PATH * 2], p[MAX_PATH * 2]; WIN32_FIND_DATAA fd; int bad = 0;
    snprintf(q, sizeof q, "%s\\*", path);
    HANDLE h = FindFirstFileA(q, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
            snprintf(p, sizeof p, "%s\\%s", path, fd.cFileName);
            if (p_rmtree(p)) bad = 1;
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    if (!RemoveDirectoryA(path)) MoveFileExA(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    return bad ? -1 : 0;
}

int p_read_secret(const char *prompt, char *buf, size_t cap)
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE), out = GetStdHandle(STD_ERROR_HANDLE);
    DWORD m = 0, w; int con = GetConsoleMode(in, &m);
    WriteFile(out, prompt, (DWORD)strlen(prompt), &w, NULL);
    if (con) SetConsoleMode(in, m & ~(DWORD)ENABLE_ECHO_INPUT);
    size_t n = 0; char c; DWORD r;
    while (n < cap - 1 && ReadFile(in, &c, 1, &r, NULL) && r == 1 && c != '\n') if (c != '\r') buf[n++] = c;
    buf[n] = 0;
    if (con) { SetConsoleMode(in, m); WriteFile(out, "\r\n", 2, &w, NULL); }
    return n ? 0 : -1;
}
