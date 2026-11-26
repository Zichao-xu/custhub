/* 平台模块: POSIX(Linux / OpenWrt / macOS)。只有这里和 plat_win.c 能 include 系统头文件 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700                 /* posix_openpt / grantpt / ptsname(glibc 要它) */
#endif
#include "plat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <pwd.h>
#include <grp.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/stat.h>
#include <dirent.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

static int would(int e) { return e == EAGAIN || e == EWOULDBLOCK || e == EINTR; }

#ifdef __linux__
static void android_tz(void);
static int tz_ours;
#endif
int p_init(void)
{
    signal(SIGPIPE, SIG_IGN);
#ifdef __linux__
    android_tz();
#endif
    return 0;
}

int p_poll(pfd_t *p, int n, int ms)
{
    static struct pollfd q[1024];
    if (n > (int)(sizeof q / sizeof q[0])) n = (int)(sizeof q / sizeof q[0]);
    for (int i = 0; i < n; i++) {
        q[i].fd = p[i].fd; q[i].revents = 0;
        q[i].events = (short)((p[i].ev & P_IN ? POLLIN : 0) | (p[i].ev & P_OUT ? POLLOUT : 0));
    }
    int r = poll(q, (nfds_t)n, ms);
    if (r < 0) return errno == EINTR ? 0 : -1;
    for (int i = 0; i < n; i++)
        p[i].rev = (short)((q[i].revents & POLLIN ? P_IN : 0) | (q[i].revents & POLLOUT ? P_OUT : 0) |
                           (q[i].revents & (POLLHUP | POLLERR | POLLNVAL) ? P_HUP : 0));
    return r;
}

/* 一律 read / write: socket、伪终端、标准输入输出都能用(SIGPIPE 已忽略; SO_NOSIGPIPE 兜底 macOS) */
long p_recv(int fd, void *b, size_t n)
{
    ssize_t r = read(fd, b, n);
    if (r >= 0) return (long)r;
    if (errno == EIO) return 0;                         /* 伪终端: shell 那头全关了 = 读到头 */
    return would(errno) ? P_AGAIN : P_FAIL;
}

long p_send(int fd, const void *b, size_t n)
{
    ssize_t r = write(fd, b, n);
    if (r >= 0) return (long)r;
    return would(errno) ? P_AGAIN : P_FAIL;
}

void p_close(int fd) { close(fd); }
void p_shut_wr(int fd) { shutdown(fd, SHUT_WR); }

void p_nb(int fd)
{
    int one = 1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

void p_block(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK); }
int p_lasterr(void) { return errno; }
const char *p_strerr(int e) { return strerror(e); }

int p_dial(const char *host, int port, int nb, char *why, size_t wcap)
{
    struct addrinfo hints, *ai = NULL;
    char ps[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &ai) || !ai) { snprintf(why, wcap, "解析不了 %s", host); return -1; }
    int fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(why, wcap, "%s", strerror(errno)); freeaddrinfo(ai); return -1; }
    if (nb) p_nb(fd);
    int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
    if (r < 0 && !(nb && errno == EINPROGRESS)) { snprintf(why, wcap, "%s", strerror(errno)); close(fd); return -1; }
    return fd;
}

int p_dial_from(const char *host, int port, int lport, char *why, size_t wcap)
{
    struct sockaddr_in a, l; int one = 1;
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) { snprintf(why, wcap, "不是 IPv4 地址: %s", host); return -1; }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(why, wcap, "%s", strerror(errno)); return -1; }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
    memset(&l, 0, sizeof l); l.sin_family = AF_INET; l.sin_port = htons((uint16_t)lport);
    if (bind(fd, (struct sockaddr *)&l, sizeof l)) { snprintf(why, wcap, "占不了本地端口 %d: %s", lport, strerror(errno)); close(fd); return -1; }
    p_nb(fd);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0 && errno != EINPROGRESS) { snprintf(why, wcap, "%s", strerror(errno)); close(fd); return -1; }
    return fd;
}

int p_dial_result(int fd)
{
    int err = 0; socklen_t l = sizeof err;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l)) return errno;
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
    int fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(ai); return -1; }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (ai->ai_family == AF_INET6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);   /* v4、v6 各开一个监听 */
    if (bind(fd, ai->ai_addr, ai->ai_addrlen) || listen(fd, 64)) { freeaddrinfo(ai); close(fd); return -1; }
    freeaddrinfo(ai);
    p_nb(fd);
    return fd;
}

int p_accept(int lfd, char *peer, size_t pcap)
{
    struct sockaddr_storage sa; socklen_t l = sizeof sa;
    int fd = accept(lfd, (struct sockaddr *)&sa, &l);
    if (fd < 0) return -1;
    char h[64] = "?"; int port = 0;
    if (sa.ss_family == AF_INET) { struct sockaddr_in *s4 = (void *)&sa; inet_ntop(AF_INET, &s4->sin_addr, h, sizeof h); port = ntohs(s4->sin_port); }
    else if (sa.ss_family == AF_INET6) { struct sockaddr_in6 *s6 = (void *)&sa; inet_ntop(AF_INET6, &s6->sin6_addr, h, sizeof h); port = ntohs(s6->sin6_port); }
    if (peer) snprintf(peer, pcap, strchr(h, ':') ? "[%s]:%d" : "%s:%d", h, port);   /* IPv6 带方括号 */
    p_nb(fd);
    return fd;
}

void p_open_firewall(int port)
{
#ifdef __linux__
    char cmd[300];
    snprintf(cmd, sizeof cmd, "command -v iptables >/dev/null 2>&1 && { iptables -C INPUT -p tcp --dport %d -j ACCEPT 2>/dev/null"
             " || iptables -I INPUT 1 -p tcp --dport %d -j ACCEPT; } >/dev/null 2>&1", port, port);
    if (system(cmd)) { /* 没有 iptables 或没权限: 不影响 */ }
    snprintf(cmd, sizeof cmd, "command -v ip6tables >/dev/null 2>&1 && { ip6tables -C INPUT -p tcp --dport %d -j ACCEPT 2>/dev/null"
             " || ip6tables -I INPUT 1 -p tcp --dport %d -j ACCEPT; } >/dev/null 2>&1", port, port);
    if (system(cmd)) { /* 同上, IPv6 */ }
    snprintf(cmd, sizeof cmd, "command -v iptables >/dev/null 2>&1 && { iptables -C INPUT -p udp --dport %d -j ACCEPT 2>/dev/null"
             " || iptables -I INPUT 1 -p udp --dport %d -j ACCEPT; } >/dev/null 2>&1", port, port);
    if (system(cmd)) { /* UDP 链路 */ }
    /* OpenWrt fw4(nftables): iptables 那条进不了 fw4 的 input_wan, WAN 进来的照样被拒; 写一条 uci 规则(重载后还在) + 当场插进去 */
    char fw[1400];
    snprintf(fw, sizeof fw, "[ -x /sbin/fw4 ] && command -v uci >/dev/null 2>&1 && command -v nft >/dev/null 2>&1 && {"
             " { [ \"$(uci -q get firewall.custhub.dest_port)\" = %d ] && [ \"$(uci -q get firewall.custhub.proto)\" = 'tcp udp' ]; } || { uci -q delete firewall.custhub; uci set firewall.custhub=rule;"
             " uci set firewall.custhub.name=custhub; uci set firewall.custhub.src=wan; uci set firewall.custhub.proto='tcp udp';"
             " uci set firewall.custhub.dest_port=%d; uci set firewall.custhub.target=ACCEPT; uci commit firewall; };"
             " nft list chain inet fw4 input_wan | grep -q 'tcp dport %d .*accept' || nft insert rule inet fw4 input_wan tcp dport %d counter accept comment custhub;"
             " nft list chain inet fw4 input_wan | grep -q 'udp dport %d .*accept' || nft insert rule inet fw4 input_wan udp dport %d counter accept comment custhub; } >/dev/null 2>&1",
             port, port, port, port, port, port);
    if (system(fw)) { /* 不是 fw4 的 OpenWrt: 不影响 */ }
#else
    (void)port;
#endif
}

int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int64_t wall_ms(void) { struct timeval tv; gettimeofday(&tv, NULL); return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000; }

void rnd(uint8_t *out, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    while (fd >= 0 && got < n) { ssize_t r = read(fd, out + got, n - got); if (r <= 0) break; got += (size_t)r; }
    if (fd >= 0) close(fd);
    if (got != n) { fprintf(stderr, "取不到随机数\n"); abort(); }
}

int p_replace(const char *from, const char *to) { return rename(from, to) ? -1 : 0; }
void *p_fopen(const char *path, const char *mode) { return fopen(path, mode); }
int p_fseek64(void *f, int64_t off) { return fseeko((FILE *)f, (off_t)off, SEEK_SET) ? -1 : 0; }
int64_t p_fsize(const char *path) { struct stat st; return !stat(path, &st) && S_ISREG(st.st_mode) ? (int64_t)st.st_size : -1; }
int p_stderr_tty(void) { return isatty(2); }
void p_hide_console(void) { }

static int as_write(const char *p, const char *t, size_t n)
{
    FILE *f = fopen(p, "wb");
    if (!f) return -1;
    int ok = fwrite(t, 1, n, f) == n;
    return fclose(f) || !ok ? -1 : 0;
}

static void as_path(const char *name, char *p, size_t cap)
{
    const char *h = getenv("HOME") ? getenv("HOME") : "";
#ifdef __APPLE__
    snprintf(p, cap, "%s/Library/LaunchAgents/com.custhub.%s.plist", h, name);
#else
    snprintf(p, cap, "%s/.config/autostart/custhub-%s.desktop", h, name);
#endif
}

int p_autostart_on(const char *name) { char p[1100]; as_path(name, p, sizeof p); return access(p, F_OK) == 0; }

int p_autostart(const char *name, int on, const char *args, char *why, size_t wcap)
{
    char p[1100], self[1200], cmd[2600], t[3000]; as_path(name, p, sizeof p);
    if (p_self_path(self, sizeof self)) { snprintf(why, wcap, "找不到本程序的路径"); return -1; }
#ifdef __APPLE__
    snprintf(cmd, sizeof cmd, "launchctl unload -w '%s' >/dev/null 2>&1", p);
    if (system(cmd)) { /* 原来没装: 不要紧 */ }
    if (!on) { remove(p); return 0; }
    char d[1100]; snprintf(d, sizeof d, "%s/Library/LaunchAgents", getenv("HOME") ? getenv("HOME") : ""); mkdir(d, 0755);
    char argx[1200] = ""; size_t al = 0; char a2[400]; snprintf(a2, sizeof a2, "%s", args);
    for (char *sv = NULL, *w = strtok_r(a2, " ", &sv); w; w = strtok_r(NULL, " ", &sv)) al += (size_t)snprintf(argx + al, sizeof argx - al, "<string>%s</string>", w);
    int n = snprintf(t, sizeof t, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                     "<plist version=\"1.0\"><dict><key>Label</key><string>com.custhub.%s</string><key>ProgramArguments</key><array><string>%s</string>%s</array>"
                     "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ProcessType</key><string>Background</string></dict></plist>\n", name, self, argx);
    if (as_write(p, t, (size_t)n)) { snprintf(why, wcap, "写不了 %s", p); return -1; }
    snprintf(cmd, sizeof cmd, "launchctl load -w '%s' >/dev/null 2>&1", p);
    if (system(cmd)) { snprintf(why, wcap, "launchctl 没装上"); return -1; }
    return 0;
#else
    snprintf(cmd, sizeof cmd, "pkill -f '%s %s' >/dev/null 2>&1", self, args);
    if (system(cmd)) { /* 没在跑 */ }
    if (!on) { remove(p); return 0; }
    char d[1100]; snprintf(d, sizeof d, "%s/.config", getenv("HOME") ? getenv("HOME") : ""); mkdir(d, 0755);
    snprintf(d, sizeof d, "%s/.config/autostart", getenv("HOME") ? getenv("HOME") : ""); mkdir(d, 0755);
    int n = snprintf(t, sizeof t, "[Desktop Entry]\nType=Application\nName=custhub %s\nExec=%s %s\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n", name, self, args);
    if (as_write(p, t, (size_t)n)) { snprintf(why, wcap, "写不了 %s", p); return -1; }
    snprintf(cmd, sizeof cmd, "nohup '%s' %s >/dev/null 2>&1 &", self, args);   /* 这次登录也马上起来 */
    if (system(cmd)) { snprintf(why, wcap, "起不来"); return -1; }
    return 0;
#endif
}
void p_notify(const char *title, const char *msg)
{
    char t[200], m[400], cmd[800]; size_t k = 0;   /* 去掉引号和反斜杠, 免得拼命令出问题 */
    for (const char *c = title; *c && k < sizeof t - 1; c++) if (*c != '"' && *c != '\\' && *c != '\'' && *c != '`' && *c != '$') t[k++] = *c;
    t[k] = 0; k = 0;
    for (const char *c = msg; *c && k < sizeof m - 1; c++) if (*c != '"' && *c != '\\' && *c != '\'' && *c != '`' && *c != '$') m[k++] = *c;
    m[k] = 0;
#ifdef __APPLE__
    snprintf(cmd, sizeof cmd, "osascript -e 'display notification \"%s\" with title \"%s\"' >/dev/null 2>&1", m, t);
#else
    snprintf(cmd, sizeof cmd, "command -v notify-send >/dev/null 2>&1 && notify-send '%s' '%s' >/dev/null 2>&1", t, m);
#endif
    if (system(cmd)) { /* 没有通知服务: 不影响 */ }
}
int p_isdir(const char *path) { struct stat st; return !stat(path, &st) && S_ISDIR(st.st_mode); }
int p_remove(const char *path) { return remove(path); }
char p_sep(void) { return '/'; }

int p_pump_stdio(int fd)
{
    char b[16384];
    struct pollfd p[2] = { { 0, POLLIN, 0 }, { fd, POLLIN, 0 } };
    for (;;) {
        if (poll(p, 2, -1) < 0) { if (errno == EINTR) continue; return 1; }
        if (p[0].revents) {
            ssize_t r = read(0, b, sizeof b);
            if (r <= 0) { shutdown(fd, SHUT_WR); p[0].fd = -1; }
            else for (ssize_t o = 0; o < r;) { ssize_t w = send(fd, b + o, (size_t)(r - o), 0); if (w <= 0) return 1; o += w; }
        }
        if (p[1].revents) {
            ssize_t r = recv(fd, b, sizeof b, 0);
            if (r <= 0) return 0;
            for (ssize_t o = 0; o < r;) { ssize_t w = write(1, b + o, (size_t)(r - o)); if (w <= 0) return 1; o += w; }
        }
    }
}

long p_agent_call(const uint8_t *req, size_t n, uint8_t *resp, size_t cap, char *why, size_t wcap)
{
    const char *path = getenv("SSH_AUTH_SOCK");
    struct sockaddr_un a;
    if (!path || !*path || strlen(path) >= sizeof a.sun_path) { snprintf(why, wcap, "没有 ssh-agent(SSH_AUTH_SOCK 没设)"); return -1; }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(why, wcap, "%s", strerror(errno)); return -1; }
    memset(&a, 0, sizeof a); a.sun_family = AF_UNIX; memcpy(a.sun_path, path, strlen(path));
    if (connect(fd, (struct sockaddr *)&a, sizeof a)) { snprintf(why, wcap, "连不上 ssh-agent: %s", strerror(errno)); close(fd); return -1; }
    for (size_t o = 0; o < n;) { ssize_t w = write(fd, req + o, n - o); if (w <= 0) { snprintf(why, wcap, "写 ssh-agent 失败"); close(fd); return -1; } o += (size_t)w; }
    uint8_t h[4]; size_t got = 0;
    while (got < 4) { ssize_t r = read(fd, h + got, 4 - got); if (r <= 0) break; got += (size_t)r; }
    size_t len = got == 4 ? (size_t)h[0] << 24 | (size_t)h[1] << 16 | (size_t)h[2] << 8 | h[3] : 0;
    if (got != 4 || len == 0 || len > cap) { snprintf(why, wcap, "ssh-agent 回答不对"); close(fd); return -1; }
    for (got = 0; got < len;) { ssize_t r = read(fd, resp + got, len - got); if (r <= 0) { snprintf(why, wcap, "ssh-agent 回答不完整"); close(fd); return -1; } got += (size_t)r; }
    close(fd);
    return (long)len;
}

/* ---------- 伪终端 ---------- */
int p_pair(int fd[2])
{
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) return -1;
    for (int i = 0; i < 2; i++) { fcntl(fd[i], F_SETFD, FD_CLOEXEC); fcntl(fd[i], F_SETFL, fcntl(fd[i], F_GETFL) | O_NONBLOCK); }
    return 0;
}

#define MAXPTY 32
static struct { int used, mfd, exited, code; pid_t pid; } PT[MAXPTY];

static void reap(int h)
{
    int st;
    if (PT[h].exited || !PT[h].pid) return;
    if (waitpid(PT[h].pid, &st, WNOHANG) == PT[h].pid) {
        PT[h].exited = 1;
        PT[h].code = WIFEXITED(st) ? WEXITSTATUS(st) : WIFSIGNALED(st) ? 128 + WTERMSIG(st) : 255;
    }
}

int p_pty_open(const char *cmd, int rows, int cols, const char *term, int *fd, char *why, size_t wcap)
{
    int h = -1;
    for (int i = 0; i < MAXPTY; i++) {
        if (PT[i].used == 2) { reap(i); if (PT[i].exited) PT[i].used = 0; }   /* 关过但还没收尸的 */
        if (!PT[i].used && h < 0) h = i;
    }
    if (h < 0) { snprintf(why, wcap, "shell 太多了"); return -1; }
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) || unlockpt(m)) { snprintf(why, wcap, "开不了伪终端: %s", strerror(errno)); if (m >= 0) close(m); return -1; }
    const char *sn = ptsname(m);
    char sname[128]; snprintf(sname, sizeof sname, "%s", sn ? sn : "");
    struct winsize ws; memset(&ws, 0, sizeof ws); ws.ws_row = (unsigned short)rows; ws.ws_col = (unsigned short)cols;
    /* 终端设置在 fork 前由这边设好: 输入可能在 shell 起来之前就到了, 不能让它先按默认设置回显 */
    int s0 = open(sname, O_RDWR | O_NOCTTY);
    if (s0 < 0) { snprintf(why, wcap, "开不了伪终端从端: %s", strerror(errno)); close(m); return -1; }
    ioctl(s0, TIOCSWINSZ, &ws);
    if (cmd) {                                          /* 跑命令: 不回显输入、输出不转换换行, 对脚本友好(输出逐字节原样) */
        struct termios t;
        if (!tcgetattr(s0, &t)) { t.c_lflag &= ~(unsigned)(ECHO | ECHONL | ECHOCTL); t.c_oflag &= ~(unsigned)OPOST; tcsetattr(s0, TCSANOW, &t); }
    }
    pid_t pid = fork();
    if (pid < 0) { snprintf(why, wcap, "fork 失败: %s", strerror(errno)); close(s0); close(m); return -1; }
    if (pid == 0) {
        setsid();
        int s = open(sname, O_RDWR);
        if (s < 0) _exit(127);
#ifdef TIOCSCTTY
        ioctl(s, TIOCSCTTY, 0);
#endif
        dup2(s, 0); dup2(s, 1); dup2(s, 2);
        for (int f = 3; f < 1024; f++) close(f);
        /* 信号恢复成默认、清空屏蔽字(和 sshd 一样): 守护进程若是从非交互 shell 放到后台起的, SIGINT 等会被设成忽略,
         * 一路传给 shell, Ctrl-C 之后 shell 就不收拾前台命令了 */
        for (int sg = 1; sg < 32; sg++) if (sg != SIGKILL && sg != SIGSTOP) signal(sg, SIG_DFL);
        sigset_t none; sigemptyset(&none); sigprocmask(SIG_SETMASK, &none, NULL);
        struct passwd *pw = getpwuid(getuid());
        const char *sh = pw && pw->pw_shell && *pw->pw_shell ? pw->pw_shell : "/bin/sh";
        if (pw) { setenv("HOME", pw->pw_dir, 1); setenv("USER", pw->pw_name, 1); setenv("LOGNAME", pw->pw_name, 1); }
        setenv("SHELL", sh, 1);
#ifdef __linux__
        if (tz_ours) unsetenv("TZ");                    /* 安卓上给自己设的时区, 不传给 shell */
#endif
        setenv("TERM", term && *term ? term : "xterm-256color", 1);
        if (cmd) { execl("/bin/sh", "sh", "-c", cmd, (char *)NULL); _exit(127); }
        if (pw && pw->pw_dir && chdir(pw->pw_dir)) { /* 进不了家目录就留在原地 */ }
        const char *b = strrchr(sh, '/');
        char a0[64]; snprintf(a0, sizeof a0, "-%s", b ? b + 1 : sh);   /* 登录 shell */
        execl(sh, a0, (char *)NULL);
        execl("/bin/sh", "-sh", (char *)NULL);
        _exit(127);
    }
    close(s0);
    fcntl(m, F_SETFD, FD_CLOEXEC); fcntl(m, F_SETFL, fcntl(m, F_GETFL) | O_NONBLOCK);
    PT[h].used = 1; PT[h].mfd = m; PT[h].pid = pid; PT[h].exited = 0; PT[h].code = 0;
    *fd = m;
    return h;
}

void p_pty_resize(int h, int rows, int cols)
{
    if (h < 0 || h >= MAXPTY || PT[h].used != 1) return;
    struct winsize ws; memset(&ws, 0, sizeof ws); ws.ws_row = (unsigned short)rows; ws.ws_col = (unsigned short)cols;
    ioctl(PT[h].mfd, TIOCSWINSZ, &ws);
}

int p_pty_exit(int h, int *code)
{
    if (h < 0 || h >= MAXPTY || !PT[h].used) return 1;
    reap(h);
    if (PT[h].exited) *code = PT[h].code;
    return PT[h].exited;
}

void p_pty_close(int h)
{
    if (h < 0 || h >= MAXPTY || PT[h].used != 1) return;
    reap(h);
    if (!PT[h].exited) kill(-PT[h].pid, SIGHUP);
    close(PT[h].mfd);
    reap(h);
    PT[h].used = PT[h].exited ? 0 : 2;                 /* 2 = 等下次收尸 */
}

/* ---------- 本地终端 ---------- */
static struct termios saved; static int raw_on;
static volatile sig_atomic_t winch;
static void on_winch(int s) { (void)s; winch = 1; }

int p_tty_raw(int on)
{
    if (!isatty(0)) return 0;
    if (on && !raw_on) {
        struct termios t;
        if (tcgetattr(0, &saved)) return 0;
        t = saved;
        t.c_iflag &= ~(unsigned)(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
        t.c_oflag &= ~(unsigned)OPOST;
        t.c_lflag &= ~(unsigned)(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        t.c_cflag &= ~(unsigned)(CSIZE | PARENB); t.c_cflag |= CS8;
        t.c_cc[VMIN] = 1; t.c_cc[VTIME] = 0;
        tcsetattr(0, TCSANOW, &t);
        raw_on = 1;
        signal(SIGWINCH, on_winch);
    } else if (!on && raw_on) { tcsetattr(0, TCSANOW, &saved); raw_on = 0; }
    return 1;
}

int p_tty_ansi(void) { return 1; }

int p_tty_size(int *rows, int *cols)
{
    struct winsize ws;
    if (ioctl(0, TIOCGWINSZ, &ws) || !ws.ws_row || !ws.ws_col) return -1;
    *rows = ws.ws_row; *cols = ws.ws_col;
    return 0;
}

int p_tty_resized(void) { int w = winch; winch = 0; return w; }

void p_pty_eof(int h)
{
    if (h < 0 || h >= MAXPTY || PT[h].used != 1) return;
    char eot = 4;                                       /* 伪终端没法半关: 给一个 ^D(行首时就是"输入到头") */
    if (write(PT[h].mfd, &eot, 1) < 0) { /* 写不进就算了 */ }
}

int p_stdin_fd(void) { return 0; }

int p_stdout_write(const void *b, size_t n)
{
    const char *p = b;
    while (n) {
        ssize_t w = write(1, p, n);
        if (w < 0 && (errno == EAGAIN || errno == EINTR)) { struct pollfd q = { 1, POLLOUT, 0 }; poll(&q, 1, 1000); continue; }
        if (w <= 0) return -1;
        p += w; n -= (size_t)w;
    }
    return 0;
}

char **p_args_utf8(int argc, char **argv) { (void)argc; return argv; }

/* ---------- UDP ---------- */
int p_udp_open(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC); fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
}

int p_udp_sendto(int fd, const char *host, int port, const void *b, size_t n)
{
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) return -1;
    return sendto(fd, b, n, 0, (struct sockaddr *)&a, sizeof a) == (ssize_t)n ? 0 : -1;
}

int p_udp_bind(int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0), big = 1 << 20;
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC); fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big); setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&a, sizeof a)) { close(fd); return -1; }
    return fd;
}

long p_udp_recvfrom(int fd, void *b, size_t cap, char *from, size_t fcap)
{
    struct sockaddr_in a; socklen_t l = sizeof a; char h[48];
    ssize_t r = recvfrom(fd, b, cap, 0, (struct sockaddr *)&a, &l);
    if (r < 0) return would(errno) ? P_AGAIN : P_FAIL;
    if (a.sin_family != AF_INET || !inet_ntop(AF_INET, &a.sin_addr, h, sizeof h)) return P_AGAIN;
    snprintf(from, fcap, "%s:%d", h, ntohs(a.sin_port));
    return (long)r;
}

long p_udp_recv(int fd, void *b, size_t cap)
{
    ssize_t r = recvfrom(fd, b, cap, 0, NULL, NULL);
    if (r >= 0) return (long)r;
    return would(errno) ? P_AGAIN : P_FAIL;
}

int p_local_ip(const char *peer_host, char *out, size_t cap)
{
    struct sockaddr_in a; socklen_t l = sizeof a;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons(9);
    if (inet_pton(AF_INET, peer_host, &a.sin_addr) != 1 || connect(fd, (struct sockaddr *)&a, sizeof a) ||
        getsockname(fd, (struct sockaddr *)&a, &l) || !inet_ntop(AF_INET, &a.sin_addr, out, (socklen_t)cap)) { close(fd); return -1; }
    close(fd);
    return 0;
}

int p_local_ip6(char *out, size_t cap)
{
    struct sockaddr_in6 a; socklen_t l = sizeof a;
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&a, 0, sizeof a); a.sin6_family = AF_INET6; a.sin6_port = htons(9);
    inet_pton(AF_INET6, "2001:4860:4860::8888", &a.sin6_addr);   /* 不发包, 只问路由表用哪个源地址 */
    int ok = !connect(fd, (struct sockaddr *)&a, sizeof a) && !getsockname(fd, (struct sockaddr *)&a, &l)
             && (a.sin6_addr.s6_addr[0] & 0xe0) == 0x20 && inet_ntop(AF_INET6, &a.sin6_addr, out, (socklen_t)cap);
    close(fd);
    if (!ok) return -1;
#ifdef __linux__
    /* 开了隐私扩展时往外连用临时地址(会换): 声明可达要用同一块网卡上的固定地址(/proc/net/if_inet6: 标志 0x01 临时、0x20 弃用、0x40 待定) */
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (!f) return 0;
    char hx[40], dev[32], want[32] = "", line[200], src[33]; unsigned idx, plen, scope, flags;
    for (int i = 0; i < 16; i++) snprintf(src + 2 * i, 3, "%02x", a.sin6_addr.s6_addr[i]);
    while (fgets(line, sizeof line, f)) if (sscanf(line, "%32s %x %x %x %x %31s", hx, &idx, &plen, &scope, &flags, dev) == 6 && !strcmp(hx, src)) snprintf(want, sizeof want, "%s", dev);
    rewind(f);
    while (want[0] && fgets(line, sizeof line, f)) {
        if (sscanf(line, "%32s %x %x %x %x %31s", hx, &idx, &plen, &scope, &flags, dev) != 6 || strcmp(dev, want) || scope || (flags & 0x61)) continue;
        unsigned char b[16]; for (int i = 0; i < 16; i++) { unsigned v; sscanf(hx + 2 * i, "%2x", &v); b[i] = (unsigned char)v; }
        if ((b[0] & 0xe0) != 0x20) continue;
        char t[64]; if (inet_ntop(AF_INET6, b, t, sizeof t)) snprintf(out, cap, "%s", t);
        break;
    }
    fclose(f);
#endif
    return 0;
}

int p_local_ipv4s(char (*out)[48], int max)
{
    struct ifaddrs *ia = NULL; int n = 0;
    if (getifaddrs(&ia)) return 0;
    for (struct ifaddrs *i = ia; i && n < max; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in *a = (struct sockaddr_in *)i->ifa_addr;
        if ((ntohl(a->sin_addr.s_addr) >> 24) == 127) continue;
        if (inet_ntop(AF_INET, &a->sin_addr, out[n], 48)) n++;
    }
    freeifaddrs(ia);
    return n;
}

/* ---------- 自升级 ---------- */
int p_self_path(char *out, size_t cap)
{
#ifdef __APPLE__
    extern int _NSGetExecutablePath(char *, uint32_t *);
    char tmp[1024]; uint32_t n = sizeof tmp;
    if (_NSGetExecutablePath(tmp, &n) != 0 || !realpath(tmp, out)) return -1;
    (void)cap;
    return 0;
#else
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0) return -1;
    out[n] = 0;
    return 0;
#endif
}

int p_run(const char *const *argv, char *out, size_t cap, int timeout_s)
{
    int fd[2];
    if (pipe(fd)) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); return -1; }
    if (pid == 0) {
        close(fd[0]); dup2(fd[1], 1); dup2(fd[1], 2);
        int nul = open("/dev/null", O_RDONLY); if (nul >= 0) dup2(nul, 0);
        for (int f = 3; f < 1024; f++) close(f);
        execvp(argv[0], (char *const *)argv); _exit(127);   /* 查 PATH: systemctl / launchctl 不写全路径 */
    }
    close(fd[1]);
    size_t n = 0; int timed = 0;
    time_t end = time(NULL) + timeout_s;
    for (;;) {
        int left = (int)(end - time(NULL));
        if (left <= 0) { timed = 1; break; }
        struct pollfd q = { fd[0], POLLIN, 0 };
        int r = poll(&q, 1, left * 1000);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { timed = 1; break; }
        char tmp[4096];
        ssize_t k = read(fd[0], tmp, sizeof tmp);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;
        if (out && n + 1 < cap) { size_t c = (size_t)k < cap - 1 - n ? (size_t)k : cap - 1 - n; memcpy(out + n, tmp, c); n += c; }
    }
    close(fd[0]);
    if (out) out[n] = 0;
    if (timed) kill(pid, SIGKILL);
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (timed) return -2;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

void p_make_exec(const char *path) { chmod(path, 0755); }

void p_exec_self(const char *exe, const char *const *argv) { execv(exe, (char *const *)argv); }

#define MAXFETCH 8
static pid_t FP[MAXFETCH];

int p_fetch_start(const char *url, const char *out)
{
    int h = -1;
    for (int i = 0; i < MAXFETCH && h < 0; i++) if (!FP[i]) h = i;
    if (h < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {                                     /* 依次试系统里有的下载工具, 有一个成功就算成功 */
        int nul = open("/dev/null", O_RDWR); if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        for (int f = 3; f < 1024; f++) close(f);
        signal(SIGPIPE, SIG_DFL);
        const char *t[3][10] = {
            { "curl", "-fsSL", "--connect-timeout", "15", "--max-time", "600", "-o", out, url, NULL },
            { "wget", "-q", "-T", "30", "-O", out, url, NULL },
            { "uclient-fetch", "-q", "-T", "30", "-O", out, url, NULL } };
        for (int k = 0; k < 3; k++) {
            pid_t c = fork();
            if (c == 0) { execvp(t[k][0], (char *const *)t[k]); _exit(127); }
            int st = 0;
            if (c > 0 && waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0) _exit(0);
            unlink(out);
        }
        _exit(1);
    }
    FP[h] = pid;
    return h;
}

int p_fetch_poll(int h)
{
    if (h < 0 || h >= MAXFETCH || !FP[h]) return -1;
    int st;
    pid_t r = waitpid(FP[h], &st, WNOHANG);
    if (r == 0) return 0;
    FP[h] = 0;
    return r > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 1 : -1;
}

void p_fetch_kill(int h)
{
    if (h < 0 || h >= MAXFETCH || !FP[h]) return;
    kill(FP[h], SIGKILL); waitpid(FP[h], NULL, 0); FP[h] = 0;
}

/* ---------- 部署 ---------- */
static int is_file(const char *p) { struct stat st; return stat(p, &st) == 0 && S_ISREG(st.st_mode); }
#ifdef __linux__
static int is_android(void) { static int a = -1; if (a < 0) a = is_file("/system/bin/getprop"); return a; }
#else
static int is_android(void) { return 0; }
#endif
static int is_dir(const char *p) { struct stat st; return stat(p, &st) == 0 && S_ISDIR(st.st_mode); }

static int user_mode;
void p_set_user_mode(int on) { user_mode = on; }
int p_user_mode(void) { return user_mode; }

const char *p_user_dir(void)
{
    static char d[1024];
    const char *h = getenv("HOME");
    if (!h || !*h) { struct passwd *pw = getpwuid(getuid()); h = pw ? pw->pw_dir : "/tmp"; }
    snprintf(d, sizeof d, "%s/.custhub", h);
    return d;
}

const char *p_install_dir(void)
{
    const char *e = getenv("CUSTHUB_HOME");
    if (e && *e) return e;
    if (user_mode) return p_user_dir();
#ifdef __APPLE__
    return "/Library/Application Support/custhub";
#else
#ifdef __linux__
    if (is_android()) return "/data/local/tmp/custhub";  /* adb 身份能写、能执行的地方 */
#endif
    return is_file("/etc/openwrt_release") ? "/usr/lib/custhub" : "/opt/custhub";
#endif
}

int p_is_admin(void) { return geteuid() == 0 || (is_android() && geteuid() == 2000); }   /* 安卓: adb 身份就能装 */
int p_mkdir(const char *path) { return mkdir(path, 0700) == 0 || errno == EEXIST ? 0 : -1; }
void p_private_files(void) { umask(077); }
int p_private_dir(const char *path) { return chmod(path, 0700) ? -1 : 0; }
/* ---------- 安卓 ----------
 * 和其他 Linux 用同一份程序, 运行时认: 有 /system/bin/getprop 就是。系统信息都在系统属性里(没有 os-release; 主机名恒为 localhost; 没有 zoneinfo) */
#ifdef __linux__
static struct { const char *k; char v[96]; } AP[] = {
    { "ro.product.manufacturer", "" }, { "ro.product.model", "" }, { "ro.build.version.release", "" }, { "ro.build.version.incremental", "" },
    { "ro.product.marketname", "" }, { "ro.config.marketing_name", "" }, { "ro.vendor.oplus.market.name", "" }, { "ro.vivo.market.name", "" } };   /* 后四个: 各厂家的商品名 */
#define NAP (sizeof AP / sizeof AP[0])
static const char *aprop(const char *key)               /* 一次读出要用的属性(每行 "[名字]: [值]"), 之后都用缓存 */
{
    static int got;
    if (!got) {
        got = 1;
        FILE *f = popen("/system/bin/getprop 2>/dev/null", "r");
        char l[600];
        while (f && fgets(l, sizeof l, f)) {
            char *m = strstr(l, "]: ["), *e = strrchr(l, ']');
            if (l[0] != '[' || !m || e < m + 4) continue;
            *m = 0; *e = 0;
            for (size_t i = 0; i < NAP; i++) if (!strcmp(l + 1, AP[i].k)) snprintf(AP[i].v, sizeof AP[i].v, "%s", m + 4);
        }
        if (f) pclose(f);
    }
    for (size_t i = 0; i < NAP; i++) if (!strcmp(key, AP[i].k)) return AP[i].v;
    return "";
}
static void android_tz(void)                            /* 时区: 问系统的 date 现在差几小时(夏令时切换要重启才跟上) */
{
    static int done;
    if (done || !is_android()) return;
    done = 1; unsetenv("TZ");                           /* 升级换程序时环境会带过来, 重新算 */
    FILE *f = popen("/system/bin/date +%z 2>/dev/null", "r");
    char z[16] = "", tz[40];
    if (f) { if (!fgets(z, sizeof z, f)) z[0] = 0; pclose(f); }
    if ((z[0] != '+' && z[0] != '-') || strspn(z + 1, "0123456789") != 4) return;
    snprintf(tz, sizeof tz, "<%.5s>%c%.2s:%.2s", z, z[0] == '+' ? '-' : '+', z + 1, z + 3);   /* POSIX 写法: 东八区是 -08:00 */
    setenv("TZ", tz, 1); tz_ours = 1;
}
#endif

void p_hostname(char *out, size_t cap)
{
    if (gethostname(out, cap)) snprintf(out, cap, "host");
    out[cap - 1] = 0;
#ifdef __linux__
    if (is_android() && !strcmp(out, "localhost")) {    /* 没起过主机名: 用商品名, 再没有用型号 */
        for (size_t i = 4; i < NAP; i++) if (aprop(AP[i].k)[0]) { snprintf(out, cap, "%s", AP[i].v); return; }
        if (aprop("ro.product.model")[0]) snprintf(out, cap, "%s", aprop("ro.product.model"));
    }
#endif
}
const char *p_plat(void)                                /* 发布包还是 linux-*(CH_PLAT), 对外报的平台是 android-* */
{
#ifdef __linux__
    static char a[40];
    if (is_android() && !strncmp(CH_PLAT, "linux-", 6)) { snprintf(a, sizeof a, "android-%s", &CH_PLAT[6]); return a; }
#endif
    return CH_PLAT;
}
void p_sleep_ms(int ms) { poll(NULL, 0, ms); }

const char *p_service_kind(void)
{
    const char *k = getenv("CUSTHUB_SVC_KIND");
    if (k && *k) return k;
    if (is_android()) return "android";
    if (user_mode) return is_dir("/Library/LaunchAgents") ? "launchd-user" : is_file("/bin/systemctl") || is_file("/usr/bin/systemctl") ? "systemd-user" : "";
    if (is_dir("/Library/LaunchDaemons")) return "launchd";
    if (is_file("/etc/openwrt_release")) return "procd";
    if (is_file("/bin/systemctl") || is_file("/usr/bin/systemctl")) return "systemd";
    return "";
}

#define SD_UNIT "/etc/systemd/system/custhub.service"
#define PROCD   "/etc/init.d/custhub"
#define PLIST   "/Library/LaunchDaemons/com.custhub.run.plist"

static int dry(void) { return getenv("CUSTHUB_SVC_DRY") != NULL; }

static char run_out[300];                                /* 上一条系统命令的输出(失败时附在报错里) */
static int run_q(const char *const *av)                /* 跑系统命令; 演练时只记下来 */
{
    if (dry()) return 0;
    char out[512];
    int r = p_run(av, out, sizeof out, 60);
    for (char *c = out; *c; c++) if (*c == '\n' || *c == '\r') *c = ' ';
    snprintf(run_out, sizeof run_out, "%s%s", r == 127 ? "找不到命令 " : "", out);
    return r;
}

static int put_file(const char *dir, const char *path, const char *text, int exec)
{
    char p[1200];
    if (dry()) {                                        /* 演练: 写到 dir/dry/<文件名> */
        const char *b = strrchr(path, '/');
        snprintf(p, sizeof p, "%s/dry", dir); p_mkdir(p);
        snprintf(p, sizeof p, "%s/dry/%s", dir, b ? b + 1 : path);
    } else snprintf(p, sizeof p, "%s", path);
    FILE *f = fopen(p, "w");
    if (!f) return -1;
    int ok = fputs(text, f) >= 0;
    ok = fclose(f) == 0 && ok;
    if (exec) chmod(p, 0755);
    return ok ? 0 : -1;
}

/* ---------- 安卓的开机启动 ----------
 * 有 root(Magisk / KernelSU / APatch 都认 /data/adb/service.d): 放一个开机脚本, 等开机完成后起 custhub, 挂了 5 秒后拉起; custhub 自己降到 adb 身份再跑
 * 没有 root: 系统不给开机入口, 只能起在后台, 重启后要有人再叫一次
 * 放过的脚本内容记在 节点目录/boot(第一行 ok / no): 内容没变就不再要 root(每次要都会弹提示), 变了(升级)由守护自己换 */
#ifdef __linux__
#define BOOT "/data/adb/service.d/custhub.sh"
static char boot_s[1600];
static const char *boot_script(const char *dir)         /* dir = 节点目录 */
{
    char h[300]; snprintf(h, sizeof h, "%s", dir); char *sl = strrchr(h, '/'); if (sl) *sl = 0;
    snprintf(boot_s, sizeof boot_s, "#!/system/bin/sh\n# custhub: 开机起, 挂了拉起(custhub join 放的, custhub remove 删)\n"
        "export PATH=$PATH:/system/bin:/system/xbin:/vendor/bin\n"
        "H=%s S=" BOOT " P=/data/adb/custhub.pid\n"
        "[ \"$1\" = loop ] || { setsid sh $S loop </dev/null >/dev/null 2>&1 & exit 0; }\n"
        "o=$(cat $P 2>/dev/null); [ -n \"$o\" ] && [ \"$o\" != $$ ] && grep -q custhub.sh /proc/$o/cmdline 2>/dev/null && exit 0\n"
        "echo $$ >$P\n"
        "until [ \"$(getprop sys.boot_completed)\" = 1 ]; do sleep 3; done\n"
        "while [ -f $S ] && [ -x $H/custhub ]; do\n"
        "  pgrep -f \"custhub run %s\" >/dev/null || $H/custhub run %s </dev/null >/dev/null 2>&1\n"
        "  sleep 5\ndone\nrm -f $P\n", h, dir, dir);
    return boot_s;
}
static int as_root(const char *cmds)                    /* 命令从标准输入喂给 root 的 sh; 返回退出码, 没有 root = 非 0 */
{
    FILE *f = popen(geteuid() == 0 ? "sh >/dev/null 2>&1" : "su -c sh >/dev/null 2>&1", "w");
    if (!f) return -1;
    fputs(cmds, f);
    int st = pclose(f);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
static int boot_mark(const char *dir, const char *want, char *state)   /* 记着的脚本和想要的一样 = 1, state 是当时的结果 */
{
    char p[1300], b[1700]; snprintf(p, sizeof p, "%s/boot", dir);
    FILE *f = fopen(p, "r"); if (!f) return 0;
    size_t n = fread(b, 1, sizeof b - 1, f); fclose(f); b[n] = 0;
    if (n < 3) return 0;
    *state = b[0];
    return !strcmp(b + 3, want);
}
static int boot_install(const char *dir)
{
    static char c[2400]; const char *s = boot_script(dir);
    char h[300]; snprintf(h, sizeof h, "%s", dir); char *sl = strrchr(h, '/'); if (sl) *sl = 0;
    snprintf(c, sizeof c, "[ -d /data/adb/service.d ] || exit 3\n[ \"$(id -u)\" = 0 ] || exit 4\ncat >" BOOT ".tmp <<'CUSTHUB_EOF' || exit 5\n%sCUSTHUB_EOF\n"
             "chmod 755 " BOOT ".tmp && mv " BOOT ".tmp " BOOT " || exit 6\nchown -R 2000:2000 %s\nsh " BOOT "\nexit 0\n", s, h);
    int bad = as_root(c);
    char p[1300]; snprintf(p, sizeof p, "%s/boot", dir);
    FILE *f = fopen(p, "w");
    if (f) { fprintf(f, "%s\n%s", bad ? "no" : "ok", s); fclose(f); }
    if (f && geteuid() == 0 && chown(p, 2000, 2000)) { /* 不影响 */ }
    return bad ? -1 : 0;
}
#endif

/* 守护启动时: 安卓上降到 adb 身份, 开机脚本没有或旧了就补(不耽误启动, 另起进程做) */
void p_run_prepare(const char *dir)
{
#ifdef __linux__
    char std[1200]; snprintf(std, sizeof std, "%s/node", p_install_dir());
    if (!is_android() || strcmp(dir, std)) return;
    if (geteuid() == 0) {
        static const gid_t gs[] = { 2000, 1004, 1007, 1011, 1015, 1028, 1078, 1079, 3001, 3002, 3003, 3006, 3009, 3011 };   /* adb shell 的那些组 */
        if (setgroups(sizeof gs / sizeof gs[0], gs) || setgid(2000) || setuid(2000)) { fprintf(stderr, "降不到 adb 身份: %s\n", strerror(errno)); exit(1); }
        prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);             /* 不然改不了自己的 SELinux 域 */
        int fd = open("/proc/self/attr/current", O_WRONLY);
        if (fd >= 0) { if (write(fd, "u:r:shell:s0", 12) < 0) { /* 换不了域就留在原来的 */ } close(fd); }
    }
    char st = 0;
    if (boot_mark(dir, boot_script(dir), &st)) return;
    pid_t c = fork();
    if (c == 0) {
        if (fork()) _exit(0);
        setsid();
        for (int f = 0; f < 1024; f++) close(f);
        int nul = open("/dev/null", O_RDWR); if (nul == 0) { dup2(0, 1); dup2(0, 2); }
        boot_install(dir); _exit(0);
    }
    if (c > 0) waitpid(c, NULL, 0);
#else
    (void)dir;
#endif
}
const char *p_conf_default(void) { return is_android() ? "relay off\nupnp off\n" : ""; }   /* 手机默认只往外连, 不监听、不碰路由器 */

int p_service_install(const char *exe, const char *dir, char *why, size_t wcap)
{
    const char *k = p_service_kind();
    static char t[4096];
    if (!strcmp(k, "systemd")) {
        snprintf(t, sizeof t, "[Unit]\nDescription=custhub\nAfter=network-online.target\nWants=network-online.target\n\n"
                 "[Service]\nExecStart=\"%s\" run \"%s\"\nRestart=always\nRestartSec=5\nKillMode=process\n\n"
                 "[Install]\nWantedBy=multi-user.target\n", exe, dir);
        if (put_file(dir, SD_UNIT, t, 0)) { snprintf(why, wcap, "写不了 %s", SD_UNIT); return -1; }
        const char *a[] = { "systemctl", "daemon-reload", NULL }, *b[] = { "systemctl", "enable", "custhub", NULL }, *c[] = { "systemctl", "restart", "custhub", NULL };
        run_q(a); run_q(b);
        if (run_q(c)) { snprintf(why, wcap, "systemctl restart custhub 失败: %s", run_out); return -1; }
    } else if (!strcmp(k, "procd")) {
        snprintf(t, sizeof t, "#!/bin/sh /etc/rc.common\n# custhub: 开机起, 挂了 procd 拉起\nSTART=99\nUSE_PROCD=1\n\n"
                 "start_service() {\n\tprocd_open_instance\n\tprocd_set_param command \"%s\" run \"%s\"\n"
                 "\tprocd_set_param respawn 3600 5 0\n\tprocd_close_instance\n}\n", exe, dir);
        if (put_file(dir, PROCD, t, 1)) { snprintf(why, wcap, "写不了 %s", PROCD); return -1; }
        const char *a[] = { PROCD, "enable", NULL }, *b[] = { PROCD, "restart", NULL };
        run_q(a);
        if (run_q(b)) { snprintf(why, wcap, "%s restart 失败: %s", PROCD, run_out); return -1; }
    } else if (!strcmp(k, "launchd")) {
        snprintf(t, sizeof t, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                 "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                 "<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.custhub.run</string>\n"
                 "<key>ProgramArguments</key><array><string>%s</string><string>run</string><string>%s</string></array>\n"
                 "<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>5</integer>\n"
                 "</dict></plist>\n", exe, dir);
        if (put_file(dir, PLIST, t, 0)) { snprintf(why, wcap, "写不了 %s", PLIST); return -1; }
        const char *a[] = { "launchctl", "bootout", "system/com.custhub.run", NULL }, *b[] = { "launchctl", "bootstrap", "system", PLIST, NULL };
        run_q(a);
        if (run_q(b)) { snprintf(why, wcap, "launchctl bootstrap 失败: %s", run_out); return -1; }
    } else if (!strcmp(k, "launchd-user")) {            /* 用户模式(Mac): 自己账号的 LaunchAgent */
        char pl[1100], dom[40]; snprintf(pl, sizeof pl, "%s/Library/LaunchAgents/com.custhub.run.plist", getenv("HOME") ? getenv("HOME") : "");
        snprintf(dom, sizeof dom, "gui/%d", (int)getuid());
        snprintf(t, sizeof t, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                 "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                 "<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.custhub.run</string>\n"
                 "<key>ProgramArguments</key><array><string>%s</string><string>run</string><string>%s</string></array>\n"
                 "<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>5</integer>\n"
                 "</dict></plist>\n", exe, dir);
        if (put_file(dir, pl, t, 0)) { snprintf(why, wcap, "写不了 %s", pl); return -1; }
        char svc[60]; snprintf(svc, sizeof svc, "%s/com.custhub.run", dom);
        const char *a[] = { "launchctl", "bootout", svc, NULL }, *b[] = { "launchctl", "bootstrap", dom, pl, NULL };
        run_q(a);
        if (run_q(b)) { snprintf(why, wcap, "launchctl bootstrap %s 失败: %s", dom, run_out); return -1; }
    } else if (!strcmp(k, "systemd-user")) {            /* 用户模式(Linux): systemd --user */
        char u[1100]; snprintf(u, sizeof u, "%s/.config/systemd/user/custhub.service", getenv("HOME") ? getenv("HOME") : "");
        if (!dry()) { char d1[1100]; snprintf(d1, sizeof d1, "%s/.config", getenv("HOME")); mkdir(d1, 0755);
                      snprintf(d1, sizeof d1, "%s/.config/systemd", getenv("HOME")); mkdir(d1, 0755);
                      snprintf(d1, sizeof d1, "%s/.config/systemd/user", getenv("HOME")); mkdir(d1, 0755); }
        snprintf(t, sizeof t, "[Unit]\nDescription=custhub(用户模式)\n\n[Service]\nExecStart=\"%s\" run \"%s\"\nRestart=always\nRestartSec=5\n\n"
                 "[Install]\nWantedBy=default.target\n", exe, dir);
        if (put_file(dir, u, t, 0)) { snprintf(why, wcap, "写不了 %s", u); return -1; }
        const char *a[] = { "systemctl", "--user", "daemon-reload", NULL }, *b[] = { "systemctl", "--user", "enable", "custhub", NULL },
                   *c[] = { "systemctl", "--user", "restart", "custhub", NULL };
        run_q(a); run_q(b);
        if (run_q(c)) { snprintf(why, wcap, "systemctl --user restart custhub 失败: %s", run_out); return -1; }
#ifdef __linux__
    } else if (!strcmp(k, "android") && !dry()) {
        if (boot_install(dir)) {
            printf("  没拿到 root(或没有 /data/adb/service.d): 现在能用, 但手机重启后不会自己回来\n"); fflush(stdout);
            pid_t pid = fork();
            if (pid == 0) {
                setsid();
                int nul = open("/dev/null", O_RDWR); if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
                for (int f = 3; f < 1024; f++) close(f);
                execl(exe, exe, "run", dir, (char *)NULL); _exit(127);
            }
        } else { printf("  开机自启: 已装好\n"); fflush(stdout); }
#endif
    } else if (!strcmp(k, "android")) {                 /* 演练: 下面起 */
    } else { snprintf(why, wcap, "认不出这台机器的服务管理方式(systemd / procd / launchd)"); return -1; }
    if (dry()) {                                        /* 演练: 不碰系统, 直接在后台起 */
        pid_t pid = fork();
        if (pid == 0) {
            setsid();
            int nul = open("/dev/null", O_RDWR); if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
            for (int f = 3; f < 1024; f++) close(f);
            execl(exe, exe, "run", dir, (char *)NULL); _exit(127);
        }
        char p[1200]; snprintf(p, sizeof p, "%s/dry/pid", dir);
        FILE *f = fopen(p, "w"); if (f) { fprintf(f, "%d\n", (int)pid); fclose(f); }
    }
    return 0;
}

int p_service_remove(const char *dir, char *why, size_t wcap)
{
    const char *k = p_service_kind();
    (void)why; (void)wcap;
    if (dry()) {
        char p[1200], t[32]; snprintf(p, sizeof p, "%s/dry/pid", dir);
        FILE *f = fopen(p, "r");
        if (f) { if (fgets(t, sizeof t, f)) kill((pid_t)atoi(t), SIGTERM); fclose(f); }
        return 0;
    }
#ifdef __linux__
    if (!strcmp(k, "android")) {
        char c[600], st = 0; int r = -1;
        snprintf(c, sizeof c, "rm -f " BOOT "\no=$(cat /data/adb/custhub.pid 2>/dev/null)\n[ -n \"$o\" ] && grep -q custhub.sh /proc/$o/cmdline 2>/dev/null && kill $o\nrm -f /data/adb/custhub.pid\npkill -f 'custhub run %s'\nexit 0\n", dir);
        boot_mark(dir, "", &st);
        if (st == 'o') r = as_root(c);                  /* 放过开机脚本才去要 root */
        if (r) { char e[700]; snprintf(e, sizeof e, "pkill -f 'custhub run %s' >/dev/null 2>&1", dir); if (system(e)) { /* 没在跑 */ } }
        char p[1300]; snprintf(p, sizeof p, "%s/boot", dir); unlink(p);
        p_sleep_ms(500);
        return 0;
    }
#endif
    if (!strcmp(k, "systemd")) {
        const char *a[] = { "systemctl", "disable", "--now", "custhub", NULL }; run_q(a);
        unlink(SD_UNIT);
        const char *b[] = { "systemctl", "daemon-reload", NULL }; run_q(b);
    } else if (!strcmp(k, "procd")) {
        const char *a[] = { PROCD, "stop", NULL }, *b[] = { PROCD, "disable", NULL }; run_q(a); run_q(b);
        unlink(PROCD);
    } else if (!strcmp(k, "launchd")) {
        const char *a[] = { "launchctl", "bootout", "system/com.custhub.run", NULL }; run_q(a);
        unlink(PLIST);
    } else if (!strcmp(k, "launchd-user")) {
        char svc[60], pl[1100]; snprintf(svc, sizeof svc, "gui/%d/com.custhub.run", (int)getuid());
        snprintf(pl, sizeof pl, "%s/Library/LaunchAgents/com.custhub.run.plist", getenv("HOME") ? getenv("HOME") : "");
        const char *a[] = { "launchctl", "bootout", svc, NULL }; run_q(a);
        unlink(pl);
    } else if (!strcmp(k, "systemd-user")) {
        char u[1100]; snprintf(u, sizeof u, "%s/.config/systemd/user/custhub.service", getenv("HOME") ? getenv("HOME") : "");
        const char *a[] = { "systemctl", "--user", "disable", "--now", "custhub", NULL }; run_q(a);
        unlink(u);
        const char *b[] = { "systemctl", "--user", "daemon-reload", NULL }; run_q(b);
    }
    return 0;
}

/* 命令加进 PATH: root → /usr/local/bin/custhub(OpenWrt /usr/bin/custhub) 链到 exe; 普通用户 → ~/.local/bin/custhub,
 * 再在 ~/.zshrc(和已有的 ~/.bashrc)末尾加一行 PATH(带 "# custhub" 记号, 卸载时按记号删)
 * 那个位置已经有别人的同名文件(不是链接)就不动。演练模式不碰系统; CUSTHUB_PATH_DIR 可指定链接放哪(测试用) */
#define RC_LINE "export PATH=\"$HOME/.local/bin:$PATH\"  # custhub\n"
static void rc_edit(const char *home, const char *name, int on, int create)
{
    char p[1200]; snprintf(p, sizeof p, "%s/%s", home, name);
    static char t[262144]; size_t n = 0;
    FILE *f = fopen(p, "r");
    if (!f && !(on && create)) return;
    if (f) { n = fread(t, 1, sizeof t - 1, f); fclose(f); }
    t[n] = 0;
    if (n == sizeof t - 1) return;                      /* 太大的不碰 */
    int has = strstr(t, "# custhub") != NULL;
    if (on) {
        if (has || strstr(t, ".local/bin")) return;     /* 已经有了(我们加的, 或用户自己就有) */
        f = fopen(p, "a"); if (!f) return;
        if (n && t[n - 1] != '\n') fputc('\n', f);
        fputs(RC_LINE, f); fclose(f);
        if (create && n == 0) chmod(p, 0644);
    } else if (has) {
        f = fopen(p, "w"); if (!f) return;              /* 截断重写: 保留原来的权限 */
        for (char *l = t; *l; ) {
            char *e = strchr(l, '\n'); size_t k = e ? (size_t)(e - l + 1) : strlen(l);
            if (!(strstr(l, "# custhub") && strstr(l, "# custhub") < l + k)) fwrite(l, 1, k, f);
            l += k;
        }
        fclose(f);
    }
}

int p_path_link(const char *exe, int on, char *how, size_t cap)
{
    how[0] = 0;
    const char *pd = getenv("CUSTHUB_PATH_DIR");
    if ((dry() || is_android()) && !(pd && *pd)) return 0;
    int user = geteuid() != 0;
    const char *home = getenv("HOME");
    if (user && (!home || !*home)) { struct passwd *pw = getpwuid(getuid()); home = pw ? pw->pw_dir : NULL; }
    char d[1100], ln[1200];
    if (pd && *pd) snprintf(d, sizeof d, "%s", pd);
    else if (!user) snprintf(d, sizeof d, "%s", is_file("/etc/openwrt_release") ? "/usr/bin" : "/usr/local/bin");
    else if (home) snprintf(d, sizeof d, "%s/.local/bin", home);
    else { snprintf(how, cap, "找不到家目录"); return -1; }
    snprintf(ln, sizeof ln, "%s/custhub", d);
    struct stat st; char cur[1200]; long cl = -1;
    int there = lstat(ln, &st) == 0;
    if (there && S_ISLNK(st.st_mode)) { cl = (long)readlink(ln, cur, sizeof cur - 1); if (cl >= 0) cur[cl] = 0; }
    if (!on) {
        if (there && S_ISLNK(st.st_mode) && cl >= 0 && strstr(cur, "custhub")) unlink(ln);
        if (user && home && !(pd && *pd)) { rc_edit(home, ".zshrc", 0, 0); rc_edit(home, ".bashrc", 0, 0); rc_edit(home, ".profile", 0, 0); }
        snprintf(how, cap, "%s", ln);
        return 0;
    }
    if (there && !S_ISLNK(st.st_mode)) { snprintf(how, cap, "%s 已有别的文件, 没动它", ln); return -1; }
    if (!(there && cl >= 0 && !strcmp(cur, exe))) {
        if (!is_dir(d)) {                               /* 建出来的目录要让别人也能进(umask 是 077) */
            if (user && home) { char l1[1100]; snprintf(l1, sizeof l1, "%s/.local", home); if (!mkdir(l1, 0755)) chmod(l1, 0755); }
            if (mkdir(d, 0755) == 0) chmod(d, 0755);
        }
        if (there) unlink(ln);
        if (symlink(exe, ln)) { snprintf(how, cap, "链不了 %s: %s", ln, strerror(errno)); return -1; }
    }
    if (user && home && !(pd && *pd)) {
        const char *sh = getenv("SHELL");
        int zsh = (sh && strstr(sh, "zsh")) || is_dir("/Library");   /* Mac 默认 zsh */
        rc_edit(home, ".zshrc", 1, zsh);
        rc_edit(home, ".bashrc", 1, 0);
        snprintf(how, cap, "%s(新开的终端生效)", ln);
    } else snprintf(how, cap, "%s", ln);
    return 0;
}

/* ---------- 本机谁能用: custhub 用户组 ---------- */
#define GRP "custhub"
static int has_cmd(const char *c)
{
    static const char *dirs[] = { "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin" };
    char p[200];
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) { snprintf(p, sizeof p, "%s/%s", dirs[i], c); if (access(p, X_OK) == 0) return 1; }
    return 0;
}

int p_group_setup(char *why, size_t wcap)
{
    why[0] = 0;
    if (dry() || is_android() || getgrnam(GRP)) return 0;   /* 安卓没有用户组可建 */
    int r;
    if (is_dir("/Library")) { const char *a[] = { "dseditgroup", "-o", "create", "-r", "custhub users", GRP, NULL }; r = run_q(a); }
    else if (has_cmd("groupadd")) { const char *a[] = { "groupadd", "-r", GRP, NULL }; r = run_q(a); }
    else { const char *a[] = { "addgroup", "-S", GRP, NULL }; r = run_q(a); }
    if (r || !getgrnam(GRP)) { snprintf(why, wcap, "建不了用户组 %s: %s", GRP, run_out); return -1; }
    return 0;
}

void p_group_share(const char *path, int dir)
{
    if (dry()) return;
    struct group *g = getgrnam(GRP);
    if (!g || geteuid() != 0) return;
    if (chown(path, (uid_t)-1, g->gr_gid) == 0) chmod(path, dir ? 0710 : 0640);
}

int p_group_user(const char *user, int add, char *why, size_t wcap)
{
    why[0] = 0;
    if (!getpwnam(user)) { snprintf(why, wcap, "没有账号 %s", user); return -1; }
    if (dry()) return 0;
    if (p_group_setup(why, wcap)) return -1;
    int r;
    if (is_dir("/Library")) { const char *a[] = { "dseditgroup", "-o", "edit", add ? "-a" : "-d", user, "-t", "user", GRP, NULL }; r = run_q(a); }
    else if (add && has_cmd("usermod")) { const char *a[] = { "usermod", "-aG", GRP, user, NULL }; r = run_q(a); }
    else if (!add && has_cmd("gpasswd")) { const char *a[] = { "gpasswd", "-d", user, GRP, NULL }; r = run_q(a); }
    else { const char *a[] = { add ? "addgroup" : "delgroup", user, GRP, NULL }; r = run_q(a); }
    if (r) { snprintf(why, wcap, "%s", run_out); return -1; }
    return 0;
}

int p_group_list(char *out, size_t cap)
{
    out[0] = 0;
    struct group *g = getgrnam(GRP);
    if (!g) return -1;
    size_t n = 0;
    for (char **m = g->gr_mem; m && *m && n < cap - 1; m++) n += (size_t)snprintf(out + n, cap - n, "%s%s", n ? " " : "", *m);
    return 0;
}

int p_group_member(void)
{
    if (p_is_admin()) return 1;
    struct group *g = getgrnam(GRP);
    if (!g) return 0;
    gid_t l[256]; int n = getgroups(256, l);
    for (int i = 0; i < n; i++) if (l[i] == g->gr_gid) return 1;
    return getegid() == g->gr_gid;
}

void p_public_dir(const char *path) { if (!dry()) chmod(path, 0755); }

void p_username(char *out, size_t cap)
{
    struct passwd *pw = getpwuid(geteuid());
    if (pw) snprintf(out, cap, "%s", pw->pw_name);
    else snprintf(out, cap, "uid %u", (unsigned)geteuid());   /* 安卓的 /etc/passwd 是空的 */
}

const char *p_invoker(void)
{
    const char *u = getenv("SUDO_USER");
    return u && *u && strcmp(u, "root") ? u : NULL;
}

int p_elevate(int argc, char **argv)
{
    if (geteuid() == 0 || !has_cmd("sudo")) return -1;
    char self[1200];
    if (p_self_path(self, sizeof self)) return -1;
    static char *av[80]; int k = 0;
    av[k++] = "sudo"; av[k++] = "--preserve-env=SSH_AUTH_SOCK,CUSTHUB_PASSPHRASE"; av[k++] = self;
    for (int i = 1; i < argc && k < 79; i++) av[k++] = argv[i];
    av[k] = NULL;
    fflush(stdout); fflush(stderr);
    execvp("sudo", av);
    return -1;
}

/* ---------- 本机是什么机器 ---------- */
#ifndef __APPLE__
static void read_line_file(const char *p, char *out, size_t cap)
{
    out[0] = 0; FILE *f = fopen(p, "r"); if (!f) return;
    if (fgets(out, (int)cap, f)) { size_t n = strcspn(out, "\r\n"); out[n] = 0; while (n && out[n - 1] == ' ') out[--n] = 0; }
    fclose(f);
}
static void kv_file(const char *p, const char *key, char *out, size_t cap)   /* KEY="value" 这种文件 */
{
    out[0] = 0; FILE *f = fopen(p, "r"); if (!f) return;
    char l[400]; size_t kl = strlen(key);
    while (fgets(l, sizeof l, f)) if (!strncmp(l, key, kl) && l[kl] == '=') {
        char *v = l + kl + 1; v[strcspn(v, "\r\n")] = 0;
        size_t n = strlen(v); if (n && (v[0] == '"' || v[0] == '\'')) { v++; n -= 2; if ((long)n < 0) n = 0; v[n] = 0; }
        snprintf(out, cap, "%s", v); break;
    }
    fclose(f);
}
#endif
void p_machine(char *os, size_t ocap, char *model, size_t mcap)
{
    os[0] = model[0] = 0;
#ifdef __APPLE__
    char v[64] = "", m[96] = ""; size_t n = sizeof v;
    if (!sysctlbyname("kern.osproductversion", v, &n, NULL, 0)) snprintf(os, ocap, "macOS %s", v);
    n = sizeof m;
    if (!sysctlbyname("hw.model", m, &n, NULL, 0)) snprintf(model, mcap, "Apple %s", m);
#else
#ifdef __linux__
    if (is_android()) {                                 /* "Android 12 (版本号)"、"厂家 型号" */
        const char *inc = aprop("ro.build.version.incremental"), *man = aprop("ro.product.manufacturer"), *mod = aprop("ro.product.model");
        snprintf(os, ocap, "Android %s%s%s%s", aprop("ro.build.version.release"), inc[0] ? " (" : "", inc, inc[0] ? ")" : "");
        snprintf(model, mcap, "%s%s%s", man, man[0] && mod[0] ? " " : "", mod);
        return;
    }
#endif
    if (is_file("/etc/openwrt_release")) kv_file("/etc/openwrt_release", "DISTRIB_DESCRIPTION", os, ocap);
    if (!os[0]) kv_file("/etc/os-release", "PRETTY_NAME", os, ocap);
    read_line_file("/tmp/sysinfo/model", model, mcap);                     /* OpenWrt: 路由器型号 */
    if (!model[0]) read_line_file("/proc/device-tree/model", model, mcap);  /* ARM 板子 */
    if (!model[0]) {
        char ven[64], prod[64]; read_line_file("/sys/devices/virtual/dmi/id/sys_vendor", ven, sizeof ven);
        read_line_file("/sys/devices/virtual/dmi/id/product_name", prod, sizeof prod);
        if (prod[0]) snprintf(model, mcap, "%s%s%s", ven, ven[0] ? " " : "", prod);
    }
#endif
}

void p_kill_strays(void) { }

int p_rmtree(const char *path)
{
    struct stat st;
    if (lstat(path, &st)) return 0;
    if (!S_ISDIR(st.st_mode)) return unlink(path) ? -1 : 0;
    DIR *d = opendir(path);
    int bad = 0;
    if (d) {
        struct dirent *e;
        char p[2048];
        while ((e = readdir(d))) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            snprintf(p, sizeof p, "%s/%s", path, e->d_name);
            if (p_rmtree(p)) bad = 1;
        }
        closedir(d);
    }
    return rmdir(path) || bad ? -1 : 0;
}

int p_read_secret(const char *prompt, char *buf, size_t cap)
{
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) fd = 0;
    struct termios t, o; int tty = !tcgetattr(fd, &o);
    if (write(fd == 0 ? 2 : fd, prompt, strlen(prompt)) < 0) { /* 提示写不出也照读 */ }
    if (tty) { t = o; t.c_lflag &= ~(unsigned)ECHO; t.c_lflag |= ECHONL; tcsetattr(fd, TCSANOW, &t); }
    size_t n = 0; char c;
    while (n < cap - 1 && read(fd, &c, 1) == 1 && c != '\n') buf[n++] = c;
    buf[n] = 0;
    if (tty) tcsetattr(fd, TCSANOW, &o);
    if (fd > 0) close(fd);
    return n ? 0 : -1;
}

void p_setenv(const char *k, const char *v)
{
    if (v) setenv(k, v, 1); else unsetenv(k);
}
