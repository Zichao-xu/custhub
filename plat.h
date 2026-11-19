/* 平台接口(design-v3 §0): 核心只通过这些函数碰操作系统
 * 每个目标平台编译时只链一个实现: plat_posix.c(Linux / OpenWrt / macOS)、plat_win.c(Win10 1809 起)
 * 这里只许出现 C99 标准头文件; 系统头文件只能出现在平台模块里
 * 所有 fd 都是 socket(本地服务、控制口也是) */
#ifndef PLAT_H
#define PLAT_H
#include <stddef.h>
#include <stdint.h>

/* ---------- socket ---------- */
enum { P_IN = 1, P_OUT = 2, P_HUP = 4 };   /* P_HUP: 挂断或出错(只出现在 rev 里) */
typedef struct { int fd; short ev, rev; } pfd_t;
#define P_AGAIN (-1)                        /* 非阻塞: 现在读不到 / 写不进, 下次再来 */
#define P_FAIL  (-2)                        /* 出错; 原因 p_strerr(p_lasterr()) */

int  p_init(void);                          /* 进程级初始化(Windows: WSAStartup; POSIX: 忽略 SIGPIPE) */
int  p_poll(pfd_t *p, int n, int ms);       /* 就绪个数; 被信号打断返回 0; 出错 -1 */
long p_recv(int fd, void *b, size_t n);     /* >0 字节数; 0 对方关; P_AGAIN; P_FAIL */
long p_send(int fd, const void *b, size_t n); /* >0 字节数; P_AGAIN; P_FAIL */
void p_close(int fd);
void p_shut_wr(int fd);                     /* 半关: 不再写 */
void p_nb(int fd);                          /* 非阻塞 + 不被子进程继承 + TCP_NODELAY */
void p_block(int fd);
int  p_lasterr(void);
const char *p_strerr(int e);

/* 连 host:port。nb=1 时非阻塞, 返回时连接可能还在进行(等 P_OUT 后用 p_dial_result 看结果)
 * 失败返回 -1, why 里写原因 */
int  p_dial(const char *host, int port, int nb, char *why, size_t wcap);
int  p_dial_result(int fd);                 /* 0 连上了; 否则错误号 */
int  p_listen(const char *host, int port);  /* 非阻塞监听 fd; 失败 -1 */
int  p_accept(int lfd, char *peer, size_t pcap);   /* 新 fd(非阻塞), peer = "地址:端口"; 没有 -1 */
void p_open_firewall(int port);             /* 当中继开监听后放行入站(Linux: iptables), 其他平台什么都不做 */

/* UDP(UPnP 找路由器用) */
int  p_udp_open(void);                      /* 非阻塞 UDP socket; 失败 -1 */
int  p_udp_sendto(int fd, const char *host, int port, const void *b, size_t n);   /* 0 成功 */
long p_udp_recv(int fd, void *b, size_t cap); /* >0 字节数; P_AGAIN; P_FAIL */
int  p_local_ip(const char *peer_host, char *out, size_t cap);   /* 本机去 peer_host 时用的局域网地址; 0 成功 */

/* ---------- 时间 / 随机数 / 文件 ---------- */
int64_t now_ms(void);                       /* 单调时钟毫秒 */
int64_t wall_ms(void);                      /* 1970 起的毫秒 */
void rnd(uint8_t *out, size_t n);           /* 取不到就终止程序 */
int  p_replace(const char *from, const char *to);  /* 原子改名覆盖; 0 成功 */

/* ---------- ssh-agent(持主钥匙的一方签名用; 私钥只在 agent 里, 不进本程序) ---------- */
/* 把一条完整请求(含 4 字节长度)交给 agent, 读回一条回答(不含长度) → 回答字节数; 失败 -1, why 写原因 */
long p_agent_call(const uint8_t *req, size_t n, uint8_t *resp, size_t cap, char *why, size_t wcap);

/* ---------- 伪终端(sh 服务端) ---------- */
int  p_pair(int fd[2]);                     /* 一对互连的 socket(非阻塞) */
/* 起一个带伪终端的 shell: cmd = NULL 交互登录 shell, 否则 sh -c cmd(不回显、输出逐字节原样); 返回句柄(>=0), *fd 可放进 p_poll、用 p_recv / p_send
 * 失败 -1, why 写原因 */
int  p_pty_open(const char *cmd, int rows, int cols, const char *term, int *fd, char *why, size_t wcap);
void p_pty_resize(int h, int rows, int cols);
int  p_pty_exit(int h, int *code);          /* 1 已退出(code = 退出码, 被信号杀 = 128+信号); 0 还在跑 */
void p_pty_eof(int h);                      /* 工程师那头输入到头(要先把已收到的输入写完再调): POSIX 给 ^D; Windows 跑命令时关掉子进程的标准输入 */
void p_pty_close(int h);                    /* 还在跑就挂断它(Windows: 连同它起的整棵进程树); 收尸 */

/* ---------- 本地终端(sh 客户端) ---------- */
int  p_tty_raw(int on);                     /* 标准输入是终端时切原始模式 / 恢复; 返回是不是终端 */
int  p_tty_size(int *rows, int *cols);      /* 0 拿到了 */
int  p_tty_resized(void);                   /* 上次问过之后窗口大小变过 */
int  p_read_secret(const char *prompt, char *buf, size_t cap);   /* 从终端读一行, 不回显; 0 成功 */
int  p_stdin_fd(void);                      /* 能放进 p_poll、用 p_recv 读的标准输入(Windows: 后台线程桥接成 socket) */
int  p_stdout_write(const void *b, size_t n);   /* 写完为止; 0 成功 */

/* ---------- 自升级(rel.c) ---------- */
int  p_self_path(char *out, size_t cap);    /* 本程序的完整路径; 0 成功 */
int  p_run(const char *const *argv, char *out, size_t cap, int timeout_s);   /* 跑一个程序收标准输出; 返回退出码, 超时 -2 */
void p_make_exec(const char *path);
void p_exec_self(const char *exe, const char *const *argv);   /* 换成 exe 接着跑(POSIX 同一个进程; Windows 起新的再退出); 回来 = 失败 */
/* 后台下载 url 到 out(https 借系统: curl / wget / uclient-fetch; Windows 用 WinHTTP), 不卡事件循环 */
int  p_fetch_start(const char *url, const char *out);       /* 句柄 >= 0; 失败 -1 */
int  p_fetch_poll(int h);                   /* 0 还在下; 1 下好了; -1 失败(两种结束都会收回句柄) */
void p_fetch_kill(int h);

/* ---------- 部署(join.c): 安装目录、系统服务 ---------- */
void p_set_user_mode(int on);               /* 用户模式(管理电脑): 装在自己家目录、用自己账号的登录项跑, 不要 root */
int  p_user_mode(void);
const char *p_install_dir(void);            /* 系统: /opt/custhub 等; 用户模式: ~/.custhub; 环境变量 CUSTHUB_HOME 可覆盖(测试用) */
const char *p_user_dir(void);               /* 用户模式的安装目录(不看 CUSTHUB_HOME) */
int  p_is_admin(void);
int  p_mkdir(const char *path);             /* 已存在也算成功; 新建的只有自己能进(POSIX 0700) */
void p_private_files(void);                 /* 本进程之后新建的文件只有自己能读写(POSIX umask 077); 程序一开始就调 */
int  p_private_dir(const char *path);       /* 把已有目录收紧: POSIX 0700; Windows 只留 SYSTEM 和 Administrators(子项继承); 0 成功 */
void p_hostname(char *out, size_t cap);
void p_machine(char *os, size_t ocap, char *model, size_t mcap);   /* 系统("Windows 11 专业版 24H2" / "macOS 15.1" / "Debian GNU/Linux 12" / "OpenWrt 23.05")、机型(厂家 + 型号); 取不到给空 */
void p_sleep_ms(int ms);
/* 注册系统服务: 开机起、挂了自动拉起, 跑 "exe run dir"; 注册完马上启动
 * 演练模式(环境变量 CUSTHUB_SVC_DRY=1): 服务文件写到 dir/dry/ 下, 不碰系统, 改成直接在后台起 "exe run dir"
 * 种类由 CUSTHUB_SVC_KIND=systemd|procd|launchd|task 可指定(测试用), 否则自动认 */
int  p_service_install(const char *exe, const char *dir, char *why, size_t wcap);
int  p_service_remove(const char *dir, char *why, size_t wcap);
const char *p_service_kind(void);
/* 本机谁能用(design-v3 §0 第 19 条): custhub 用户组里的账号不用 root 就能 sh / connect / ls / pass(经本机守护, 碰不到节点钥匙)
 *   POSIX: 组 custhub; 节点目录 0710 root:custhub, conf 和 ctl.token 0640 root:custhub, 其他(钥匙、通行证、日志)只给 root
 *   Windows: 本地组 custhub; conf 和 ctl.token 加一条组可读, 其他只给 SYSTEM / Administrators
 * 演练模式都不碰系统 */
int  p_group_setup(char *why, size_t wcap);                 /* 组没有就建; 0 成功(建不了也不致命) */
void p_group_share(const char *path, int dir);              /* 组可读(文件) / 组可进(目录); 没有组就什么都不做 */
int  p_group_user(const char *user, int add, char *why, size_t wcap);   /* 把账号加进 / 移出组; 0 成功 */
int  p_group_list(char *out, size_t cap);                   /* 组里的账号, 空格分隔; 0 成功 */
int  p_group_member(void);                                  /* 当前账号在不在组里(当前会话已生效的) */
void p_public_dir(const char *path);                        /* 安装目录: 谁都能进、能跑程序(POSIX 0755; Windows 加 Users 读和执行) */
void p_username(char *out, size_t cap);                     /* 当前账号名 */
const char *p_invoker(void);                                /* 用 sudo 跑时 sudo 之前的账号(Windows: 当前账号); 没有返回 NULL */
int  p_elevate(int argc, char **argv);                      /* 换成 root 重跑同一条命令(POSIX: sudo, 会问密码); 回来 = 做不到 */
/* 命令加进 PATH(on=1) / 撤掉(on=0): POSIX 在 /usr/local/bin(OpenWrt /usr/bin; 用户模式 ~/.local/bin + shell 配置)放链接,
 * Windows 把 exe 所在目录加进 PATH。how 写做了什么或为什么没做; 0 成功。演练模式不碰系统 */
int  p_path_link(const char *exe, int on, char *how, size_t cap);
int  p_rmtree(const char *path);            /* 删整个目录; 删不掉的(Windows 上正在跑的程序)安排重启后删 */           /* "systemd" / "procd" / "launchd" / "task"(Windows 计划任务) / "" */

/* ---------- 命令行 ---------- */
/* 命令行参数一律 UTF-8: POSIX 原样返回; Windows 从宽字符命令行重新取(按 ANSI 代码页拿会把中文变成问号)
 * argv 可以是整个命令行的后半截(custhub 把 argv + 1 交给 mesh), 按个数对齐末尾 */
char **p_args_utf8(int argc, char **argv);

/* ---------- 小客户端 ---------- */
int  p_pump_stdio(int fd);                  /* 标准输入输出 ↔ fd, 直到对方关; 0 正常 */

#endif
