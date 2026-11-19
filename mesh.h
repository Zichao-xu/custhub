/* custhub 网络层 POC(design-v3 §2~§3): 不依赖 SSH 的去中心化网络
 * 身份 = 节点 ed25519 公钥; 链路 = TCP + Noise IK; 中继转发 + 端到端 Noise; 名单(主钥匙签) / 位置记录(节点自签)分开
 * 单线程 poll 事件循环; 输入一律定长, 超长即拒
 * 核心不碰操作系统: 系统相关的一律经 plat.h(平台模块编译时选, design-v3 §0) */
#ifndef MESH_H
#define MESH_H
#include <stddef.h>
#include <stdint.h>

#include "plat.h"

#define MESH_VER  "0.0.1"            /* 网络层协议版本(握手里报); 程序版本是 CH_VERSION, 平台名 CH_PLAT, 都由构建时 -D 给 */
#define MAXC      128            /* 链路 */
#define MAXS      256            /* 流(转发两端各占一个) */
#define MAXT      8              /* 本机要挂的中继 */
#define MAXQ      16             /* 控制口上还没说要干什么的连接 */
#define MAXM      128            /* 名单成员 */
#define MAXR      128            /* 位置记录 */
#define MAXTEXT   (32 * 1024)    /* 名单文件 */
#define MAXMSG    65535          /* 一条 Noise 消息 */
#define CHUNK     16000          /* 一个 DATA 帧最多带的明文 */
#define WIN       (256 * 1024)   /* 每条流每个方向的在途额度(明文字节) */
#define OUTMAX    (1024 * 1024)  /* 链路发送缓冲超过这个就先不读本地数据 */
#define OUTDROP   (32 * 1024 * 1024)

/* ---------- util.c ---------- */
typedef struct { uint8_t *p; size_t len, cap; } buf_t;
int    buf_add(buf_t *b, const void *d, size_t n);
void   buf_eat(buf_t *b, size_t n);
void   buf_free(buf_t *b);
void   logf_(const char *fmt, ...);
long   b64_decode(const char *in, size_t inlen, uint8_t *out, size_t cap);
void   b64_encode(const uint8_t *in, size_t n, char *out);   /* out 至少 4*ceil(n/3)+1 */
long   m_read(const char *path, char *buf, size_t cap);
int    m_write(const char *path, const char *data, size_t len);
int    ssh_pub(const char *line, uint8_t pub[32]);           /* "ssh-ed25519 AAAA..." → 32 字节 */
int    hostport(const char *s, char *host, size_t hcap, int *port);
void   short_id(const uint8_t pub[32], char out[9]);

/* ---------- noise.c: Noise_IK_25519_ChaChaPoly_BLAKE2b ---------- */
typedef struct { uint8_t k[32]; uint64_t n; } cs_t;
typedef struct {
    uint8_t ck[64], h[64], k[32]; int hask; uint64_t n;
    uint8_t s_sec[32], s_pub[32], e_sec[32], e_pub[32], rs[32], re[32];
    int initiator;
} hs_t;
void hs_init(hs_t *h, int initiator, const uint8_t s_sec[32], const uint8_t s_pub[32], const uint8_t rs[32]);
long hs_write1(hs_t *h, const uint8_t *pl, size_t pn, uint8_t *out);          /* 发起方 → 长度 */
long hs_read1(hs_t *h, const uint8_t *in, size_t n, uint8_t *pl, size_t pcap); /* 应答方; 读完 h->rs 是对方静态公钥 */
long hs_write2(hs_t *h, const uint8_t *pl, size_t pn, uint8_t *out, cs_t *tx, cs_t *rx);
long hs_read2(hs_t *h, const uint8_t *in, size_t n, uint8_t *pl, size_t pcap, cs_t *tx, cs_t *rx);
long cs_seal(cs_t *c, const uint8_t *p, size_t n, uint8_t *out);              /* out = n+16 */
long cs_open(cs_t *c, const uint8_t *in, size_t n, uint8_t *out);             /* -1 验不过 */

/* ---------- 身份 ---------- */
typedef struct { uint8_t seed[32], edsk[64], ed[32], xsec[32], x[32]; } ident_t;
int  ident_load(const char *path, ident_t *id);
int  ident_new(const char *path, ident_t *id);
void ed_to_x(const uint8_t ed[32], uint8_t x[32]);

/* ---------- 名单 / 位置记录 (disc.c) ---------- */
typedef struct { char name[32]; uint8_t ed[32], x[32]; int relay; char addr[64], host[64]; } member_t;   /* host: 批准时记下的机器名(名单行末 host=…, 只作备注) */
typedef struct { long ver; int n; member_t m[MAXM]; char text[MAXTEXT]; size_t tlen; } trust_t;
typedef struct {
    uint8_t ed[32]; uint64_t seq; int64_t rx_ms;
    int relay; char addr[64], relays[160], status[320], ver[16], info[200];   /* info: 平台|机器名|系统|机型(空格换成 _), 跟在版本后面用 | 隔开 */
    char line[800];
} rec_t;

/* ---------- 通行证(pass.c, design-v3 §0 第 11 条) ---------- */
#define PASSMAX   4096           /* 通行证原文 */
#define PASSTO    32             /* to 最多几台 */
#define PASSLIFE  86400          /* 有效期最长 1 天 */
#define PASSSKEW  300            /* 时钟容差前后 5 分钟 */
typedef struct { uint8_t key[32]; int to_all, nto; uint8_t to[PASSTO][32]; char svc[160]; int64_t from, until; } pass_t;

/* ---------- 链路 / 流 ---------- */
enum { C_FREE, C_CONNECTING, C_HS, C_UP };
typedef struct {
    int state, fd, initiator, target, peer_relay;
    int closing;                  /* 1 = 发完就断, 不收任何帧; 3 = 名单外节点的报到链路: 发了名单, 再等一会儿它的回连测试请求 */
    int probe_for;                /* 回连测试的拨号(本机替别人测): 请求方链路下标 + 1; 0 = 不是 */
    int probe_in;                 /* 对方拨过来只为测本机端口: 握手完就断 */
    member_t *pm;                 /* 对方在名单里的那一行(握手后); 访客链路上中继这边是 NULL */
    int guest;                    /* 访客链路(design-v3 §0 第 11 条: 通行证即入场券): 中继这边 = 对方是名单外的持证人; 发起方这边 = 本机以访客身份挂上 */
    pass_t gp;                    /* 中继这边: 访客出示的通行证(只转发到它 to 里的机器, 到期断开) */
    uint8_t peer[32];             /* 对方 ed25519 公钥 */
    char addr[64];
    hs_t hs; cs_t tx, rx;
    buf_t in, out;
    int64_t born, last_rx, last_tx;
    uint32_t next_sid;
} conn_t;

enum { F_PING = 1, F_PONG, F_REC, F_TRUST, F_OPEN, F_DATA, F_FIN, F_CLOSE, F_CREDIT, F_PENDQ, F_PENDA, F_PROBE, F_PROBEA };
enum { S_FREE, S_FWD, S_INIT, S_RESP };
typedef struct {
    int kind, conn, pair, fd, up, lfin, rfin;
    char req[128];                /* 要开的服务: "port:<n>" / "sh" / "pkg:<附件名>:<位置>" */
    uint32_t sid;
    uint8_t dst[32];
    hs_t hs; cs_t tx, rx;
    buf_t lout;                   /* 待写给本地连接 */
    long credit, unacked;         /* 还能发多少 / 已写给本地还没回额度的 */
    int tried[8], ntried;
} stream_t;

typedef struct {
    uint8_t ed[32]; char name[32], addr[64], alt[64], why[96];   /* addr: 中继自报(没有就是名单); alt: 名单里的线索(与 addr 不同时轮流试) */
    int conn, flip; int64_t next_try, backoff;
} target_t;

typedef struct { int fd, authed; char line[48 * 1024]; size_t n; int64_t born; } ctlq_t;   /* 一行令牌 + 一行命令(TRUSTPUT 带整份名单) */

typedef struct {
    char dir[256], name[32];
    ident_t id;
    uint8_t master[32];
    trust_t trust; int me_relay;
    char listen[64], announce[64], ctl[64], fallback[256];
    char hello[200];              /* 报到时自报的信息(机器名、通道公钥等), 管理员批准时对照用 */
    int allow[16], nallow;
    int lfd, cfd;
    char lspec[80]; int64_t lretry_ms;  /* 中继监听(由名单决定) */
    int pq_fd, pq_wait; int64_t pq_deadline; buf_t pq_out;   /* 控制口上等着的"待批准"查询 */
    conn_t c[MAXC]; stream_t s[MAXS]; target_t t[MAXT]; int nt; ctlq_t q[MAXQ];
    rec_t r[MAXR]; int nr;
    uint64_t myseq; char mybody[700]; int64_t mypub_ms;
    int64_t last_up_ms, last_fb_ms;
    int dump;                     /* 调试: 中继把转发的 DATA 原样追加到 dir/dump */
    /* 中继资质(qual.c, design-v3 §0 第 14 条) */
    int relay_off;                /* conf: relay off = 本机不当中继, 也不开监听 */
    int probing, probe_conn; int64_t probe_next, probe_deadline, ok_since;
    char pub_addr[64];            /* 回连测试通过的对外地址 */
    char port_state[320];         /* 端口检测结果(给 ls / join 看) */
    int upnp_off, upnp_port;      /* conf: upnp off; 路由器上映射出去的外部端口(0 = 没映射) */
    char github[100];             /* conf: github 仓库(owner/name), 发布物从它的 Release 取 */
    char relbase[200];            /* conf: release_base <网址>, 发布物从这里取(自建发布源 / 镜像), 取代 GitHub 那一串 */
    char upnp_why[96];
    int quiet;                    /* 命令行工具: 没配日志文件时不往 stderr 打日志 */
    char ctl_token[33];           /* 控制口令牌: 每次启动随机生成, 写进 <目录>/ctl.token(只有 root / 管理员 / 本人读得到) */
} g_t;
extern g_t G;

void log_open(const char *path);
char *m_tok(char *s, const char *delim, char **save);   /* strtok_r(Win7 的 msvcrt 没有) */
int  cmd_mesh(int argc, char **argv);                    /* main.c: mesh 子命令入口 */
int  cmd_passcheck(char **a);
/* sshsig.c: ssh-keygen -Y sign 格式验签(只认给定公钥) → 1 通过 */
int  sshsig_verify(const char *armored, const uint8_t *msg, size_t mlen, const char *ns, uint8_t (*keys)[32], int nkeys);
int  cmd_pass(int argc, char **argv);                    /* key.c: 签发通行证 */
/* sig.c: SSHSIG 拼装 + ssh-agent 签名请求(纯计算) */
size_t ssh_keyblob(const uint8_t pub[32], uint8_t out[51]);
size_t sshsig_tbs(const char *ns, const uint8_t *msg, size_t mlen, uint8_t *out, size_t cap);      /* 要交给私钥签的那段 */
size_t sshsig_armor(const uint8_t pub[32], const char *ns, const uint8_t sig[64], char *out, size_t cap);  /* -----BEGIN SSH SIGNATURE----- … */
size_t agent_sign_req(const uint8_t pub[32], const uint8_t *data, size_t n, uint8_t *out, size_t cap);
int    agent_sign_resp(const uint8_t *r, size_t n, uint8_t sig[64]);
size_t agent_add_req(const uint8_t seed[32], const uint8_t pub[32], const char *comment, uint32_t life_s, uint8_t *out, size_t cap);
size_t agent_remove_req(const uint8_t pub[32], uint8_t *out, size_t cap);
size_t agent_list_req(uint8_t *out, size_t cap);
int    agent_list_has(const uint8_t *r, size_t n, const uint8_t pub[32]);
/* key.c: 用 ssh-agent 里的主钥匙签一段 → SSHSIG 签名原文; 失败 -1 */
long   agent_sshsig(const char *ns, const uint8_t *msg, size_t n, char *armor, size_t cap, char *why, size_t wcap);
int    cmd_key(int argc, char **argv);
/* link.c */
int  mesh_run(const char *dir);
int  listen_on(const char *spec);
void relay_sync(void);
const char *relay_addr(void);
int  conn_send(int i, int type, uint32_t sid, const void *pl, size_t n);
void conn_close(int i, const char *why);
void conn_finish(int i);                                 /* 发完已排队的就半关 */
int  conn_by_peer(const uint8_t ed[32]);
uint32_t conn_new_sid(int i);
/* hop.c */
void hop_frame(int i, int type, uint32_t sid, const uint8_t *pl, size_t n);
void hop_conn_down(int i);
int  hop_open_local(int fd, const uint8_t dst[32], const char *req);
void hop_poll_add(pfd_t *p, int *np, int *map);
void hop_io(int si, short rev);
int  route(const uint8_t dst[32], const int *avoid, int navoid);
/* disc.c */
int  mesh_conf_load(const char *dir);
int  mtrust_parse(const char *text, size_t len, trust_t *t, const uint8_t master[32]);
int  mtrust_apply(const char *text, size_t len, const char *from);
member_t *member_by_ed(const uint8_t ed[32]);
member_t *member_by_x(const uint8_t x[32]);
member_t *member_by_name(const char *name);
rec_t *rec_by_ed(const uint8_t ed[32]);
void disc_rec_in(int from, const char *line, size_t n);
void disc_on_up(int i);
void disc_tick(void);
void targets_sync(void);
void disc_pendq(int from, const uint8_t *pl, size_t n);   /* 中继: 主钥匙签名的查询 → 回待批准名单 */
void disc_penda(int from, const uint8_t *pl, size_t n);   /* 查询方: 收各中继的回答 */
void disc_pend_tick(void);
int  ed_relay(const uint8_t ed[32]);                      /* 是中继: 自己在记录里声明了, 或名单里带地址(种子线索) */
/* qual.c: 中继资质 */
void qual_tick(void);
int  me_seed(void);                                      /* 本机是名单里带地址的种子线索 */
void upnp_tick(void);                                    /* upnp.c */
/* rel.c: 发布物 + 自升级 */
long ver_cmp(const char *a, const char *b);
void rel_set_args(char *const *argv);                    /* 整个命令行(重启进新版时原样带上) */
void rel_start(void);
void rel_tick(void);
void rel_saw(const char *ver);
void rel_poll_add(pfd_t *p, int *np, int *map);          /* map 4000 */
void rel_io(int code, short rev);
int  pkg_accept(const char *req, char *why, size_t wcap);   /* pkg 服务: 返回交给连通层的本地 fd */
void pkg_poll_add(pfd_t *p, int *np, int *map);          /* map 5000 起 */
void pkg_io(int k, short rev);
const char *upnp_lan_ip(void);
void qual_probe_in(int from, const uint8_t *pl, size_t n);   /* 别人请本机替它测端口 */
void qual_probe_ans(int from, const uint8_t *pl, size_t n);  /* 本机请别人测的结果 */
int  probe_dial(const char *addr, const uint8_t x[32], int from);   /* link.c: 替 from 拨 addr, 握手证明是对方 */
const char *name_of(const uint8_t ed[32]);
/* pass.c 通行证模块(纯判断, design-v3 §0 第 11 条) */
int  pass_parse(const char *text, size_t len, const uint8_t master[32], pass_t *p, char *why, size_t wcap);   /* 验签 + 解析; 0 好 */
/* who 用这张通行证进 node(NULL = 只问能不能进网)、用 svc("sh" / "port:<n>", NULL = 不问服务)行不行; 0 行 */
int  pass_allows(const pass_t *p, const uint8_t who[32], const uint8_t node[32], const char *svc, int64_t now_s, char *why, size_t wcap);
/* svc.c 服务层: 发起方(握手证明的 x25519 公钥 rs)带着请求和通行证要开服务 → 本地 fd(非阻塞); -1 拒绝(why 写原因)
 *   who 填发起方 ed25519 公钥(取自通行证) */
int  svc_open(const uint8_t rs[32], const char *req, const char *pass, size_t plen, uint8_t who[32], char *why, size_t wcap);
/* sh.c: sh 服务 */
int  sh_accept(char *why, size_t wcap);                  /* 新会话 → 交给连通层的本地 fd */
void sh_poll_add(pfd_t *p, int *np, int *map);           /* map 编号 3000 起 */
void sh_io(int code, short rev);
void sh_tick(void);
int  cmd_sh(int argc, char **argv);
int  ctl_open(const char *dir, const char *target, const char *req);   /* app.c: 经本机守护开到对方服务的流, 返回 fd; 失败已打印原因 */
int  ctl_open_raw(const char *dir);                      /* app.c: 连本机守护的控制口 */
/* join.c: 部署 */
void join_code(const uint8_t ed[32], char out[8]);       /* 接入码 XXX-XXX */
/* kdf.c: 口令派生(同 passkey.py) */
int  scrypt_kdf(const uint8_t *pw, size_t pn, const uint8_t *salt, size_t sn, uint32_t N, int r, int p, uint8_t *out, size_t dk);
int  passphrase_seed(const char *phrase, const char *label, uint8_t seed[32]);
int  cmd_join3(int argc, char **argv);
int  cmd_run(int argc, char **argv);
void path_ensure(void);
int  cmd_user(int argc, char **argv);
int  cmd_tui(const char *dir);
const char *my_info(void);                               /* disc.c: 本机 平台|机器名|系统|机型 */                           /* tui.c: custhub 不带参数的终端界面 */                     /* custhub user add|del|ls */                                  /* 服务启动时把命令补进 PATH(安装目录里那份才做) */
int  cmd_remove3(int argc, char **argv);
const char *node_default(void);                          /* 默认节点目录(用户模式装过就用它) */
#define PASSSLOTS 8              /* 本机存的通行证: <目录>/pass, pass.1 … pass.7 */
int  pass_load(const uint8_t *dst, const char *svc, char *buf, size_t cap);   /* 发起方: 挑一张对 dst + 服务有效的(dst NULL: 没过期就行); 没有返回 0 */
int  pass_store(const char *text, size_t len, char *slot, size_t scap);       /* 存进 <目录>: 同对象同范围的替换, 否则空位 / 过期的 / 最早到期的; 0 成功 */
int  cmd_pass_local(int argc, char **argv);              /* custhub pass [文件]: 装上 / 列出本机通行证(经本机守护) */
void pass_text(buf_t *o, const char *one, size_t olen);  /* 通行证一览(守护里用) */
/* app.c */
void ctl_accept(void);
void ctl_io(int qi);
int  cmd_connect(const char *dir, const char *target, const char *port);
int  cmd_ls(const char *dir);
int  cmd_ctl(const char *dir, const char *line);
void ls_text(buf_t *o);

#endif
