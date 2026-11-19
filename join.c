/* 部署(design-v3 §0 第 17 条): custhub join / run / remove
 *   join: 种子(主公钥 + GitHub 仓库 + 种子名单) → 装进安装目录 → 节点钥匙 → conf → 注册系统服务 → 报到
 *         屏幕显示接入码(由节点公钥算出), 最多等 10 分钟看到"已接入"; 关掉也行, 服务后台接着等。可重复执行
 *   run:  系统服务跑的就是它(网络 + 自升级)
 *   remove: 注销服务、删安装目录
 * 种子 custhub3.seed(随 Release 下发; 信任起点和程序本身一样是那个 GitHub 仓库, 名单再由里面的主公钥验签):
 *   custhub-seed v1
 *   master ssh-ed25519 AAAA…
 *   github owner/name
 *   --trust--
 *   <主钥匙签的成员名单原文> */
#include "mesh.h"
#include "vendor/monocypher-ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CTL_V3 "127.0.0.1:7481"                  /* 0.2 的网络层用 7471, 同一台机器上新旧并存时不撞 */

void join_code(const uint8_t ed[32], char out[8])
{
    static const char A[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";   /* Crockford base32: 没有 I L O U, 念起来不混 */
    uint8_t h[64];
    crypto_sha512(h, ed, 32);
    uint32_t v = (uint32_t)h[0] << 22 | (uint32_t)h[1] << 14 | (uint32_t)h[2] << 6 | h[3] >> 2;   /* 前 30 位 */
    for (int i = 5; i >= 0; i--) { out[i < 3 ? i : i + 1] = A[v & 31]; v >>= 5; }
    out[3] = '-'; out[7] = 0;
}

/* 默认节点目录: 用户模式装过(~/.custhub/node 有 conf)就用它, 否则系统安装目录下的 node */
const char *node_default(void)
{
    static char d[1200]; char c[1300];
    const char *e = getenv("CUSTHUB_HOME");
    if (!e || !*e) {
        snprintf(d, sizeof d, "%s%snode", p_user_dir(), strncmp(CH_PLAT, "win", 3) ? "/" : "\\");
        snprintf(c, sizeof c, "%s%sconf", d, strncmp(CH_PLAT, "win", 3) ? "/" : "\\");
        FILE *f = fopen(c, "rb");
        if (f) { fclose(f); return d; }
    }
    snprintf(d, sizeof d, "%s%snode", p_install_dir(), strncmp(CH_PLAT, "win", 3) ? "/" : "\\");
    return d;
}

static const char *exe_name(void) { return strncmp(CH_PLAT, "win", 3) ? "custhub" : "custhub.exe"; }

static void sep_join(char *out, size_t cap, const char *a, const char *b)
{
    snprintf(out, cap, "%s%s%s", a, strncmp(CH_PLAT, "win", 3) ? "/" : "\\", b);
}

static int copy_file(const char *from, const char *to)
{
    char tmp[1200]; snprintf(tmp, sizeof tmp, "%s.tmp", to);
    FILE *a = fopen(from, "rb"), *b = fopen(tmp, "wb");
    static unsigned char buf[65536]; size_t k; int ok = a && b;
    while (ok && (k = fread(buf, 1, sizeof buf, a)) > 0) ok = fwrite(buf, 1, k, b) == k;
    if (a) fclose(a);
    if (b && fclose(b)) ok = 0;
    if (ok) { p_make_exec(tmp); ok = !p_replace(tmp, to); }
    if (!ok) remove(tmp);
    return ok ? 0 : -1;
}

/* 取种子: --seed 文件, 或从 GitHub(直连 → ghfast → gh-proxy) */
static long get_seed(const char *file, const char *repo, const char *dir, char *buf, size_t cap)
{
    if (file) return m_read(file, buf, cap);
    if (!repo) return -1;
    char out[1200]; sep_join(out, sizeof out, dir, "seed.tmp");
    static const char *pre[] = { "", "https://ghfast.top/", "https://gh-proxy.com/" };
    for (int k = 0; k < 3; k++) {
        char url[400];
        snprintf(url, sizeof url, "%shttps://github.com/%s/releases/latest/download/custhub3.seed", pre[k], repo);
        printf("  取种子: %s\n", url); fflush(stdout);
        int h = p_fetch_start(url, out), r = 0;
        for (int t = 0; h >= 0 && t < 1200 && !(r = p_fetch_poll(h)); t++) p_sleep_ms(100);
        if (r == 1) { long n = m_read(out, buf, cap); remove(out); if (n > 0) return n; }
        if (r == 0 && h >= 0) p_fetch_kill(h);
    }
    return -1;
}

static int seed_parse(char *t, char *master_line, size_t mc, char *repo, size_t rc, const char **trust)
{
    if (strncmp(t, "custhub-seed v1\n", 16)) return -1;
    char *tr = strstr(t, "\n--trust--\n");
    if (!tr) return -1;
    *tr = 0; *trust = tr + 11;
    char *m = strstr(t, "\nmaster "), *g = strstr(t, "\ngithub ");
    if (!m) return -1;
    m += 8; size_t ml = strcspn(m, "\n");
    if (ml >= mc) return -1;
    memcpy(master_line, m, ml); master_line[ml] = 0;
    repo[0] = 0;
    if (g) { g += 8; size_t gl = strcspn(g, "\n"); if (gl < rc) { memcpy(repo, g, gl); repo[gl] = 0; } }
    return 0;
}

/* 问本机守护: 第一行(本机 …)和"端口:"那行 */
static int ask_state(const char *node, char *first, size_t fc, char *port, size_t pc)
{
    int fd = ctl_open_raw(node);
    if (fd < 0) return -1;
    if (p_send(fd, "LS\n", 3) != 3) { p_close(fd); return -1; }
    static char b[16384]; size_t n = 0; long r;
    while (n < sizeof b - 1 && (r = p_recv(fd, b + n, sizeof b - 1 - n)) > 0) n += (size_t)r;
    p_close(fd);
    b[n] = 0;
    char *nl = strchr(b, '\n'); if (!nl) return -1;
    *nl = 0; snprintf(first, fc, "%s", b);
    char *p = strstr(nl + 1, "端口: ");
    port[0] = 0;
    if (p) { size_t l = strcspn(p, "\n"); if (l >= pc) l = pc - 1; memcpy(port, p, l); port[l] = 0; }
    return 0;
}

int cmd_join3(int argc, char **argv)
{
    const char *seedf = NULL, *repo = NULL; int wait_s = 600;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--seed") && i + 1 < argc) seedf = argv[++i];
        else if (!strcmp(argv[i], "--github") && i + 1 < argc) repo = argv[++i];
        else if (!strcmp(argv[i], "--wait") && i + 1 < argc) wait_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--user")) p_set_user_mode(1);
        else { fprintf(stderr, "用法: custhub join --github owner/name | --seed 文件 [--user] [--wait 秒]\n"
                               "  --user  用户模式(管理电脑): 装在自己家目录、用自己账号的登录项跑, 不要 root\n"); return 2; }
    }
    static char crepo[100];
    if (!seedf && !repo) {                              /* 重新接入 / 修复: 仓库取本机 conf 里的 github */
        char cp[1300], ct[8192]; snprintf(cp, sizeof cp, "%s%sconf", node_default(), strncmp(CH_PLAT, "win", 3) ? "/" : "\\");
        char *g = m_read(cp, ct, sizeof ct) > 0 ? strstr(ct, "github ") : NULL;
        if (g && (g == ct || g[-1] == '\n') && sscanf(g + 7, "%99s", crepo) == 1) repo = crepo;
        else { fprintf(stderr, "本机还没接入过: 第一次接入用一键命令(curl … custhub3-join.sh | sh), 或 custhub join --github owner/name\n"); return 2; }
        if (strstr(node_default(), p_user_dir()) == node_default()) p_set_user_mode(1);
    }
    if (!p_user_mode() && !p_is_admin() && !getenv("CUSTHUB_HOME")) { fprintf(stderr, "要管理员 / root 权限(Linux / Mac 前面加 sudo; Windows 用管理员身份运行)\n"); return 1; }
    const char *dir = p_install_dir();
    char node[1200], exe[1200], self[1200], p[1300];
    sep_join(node, sizeof node, dir, "node"); sep_join(exe, sizeof exe, dir, exe_name());
    if (strlen(node) >= sizeof G.dir - 40) { fprintf(stderr, "安装目录太长(最多 %d 个字节): %s\n", (int)sizeof G.dir - 40, node); return 1; }
    if (p_mkdir(dir) || p_mkdir(node)) { fprintf(stderr, "建不了 %s\n", node); return 1; }
    if (!p_user_mode()) p_public_dir(dir); else p_private_dir(dir);   /* 系统安装: 程序谁都能跑; 节点目录(钥匙、令牌)只给 root / 管理员 */
    if (p_private_dir(node)) { fprintf(stderr, "收紧不了 %s 的权限\n", node); return 1; }
    printf("custhub %s(%s)接入\n  安装目录: %s\n", CH_VERSION, CH_PLAT, dir);

    static char seed[MAXTEXT + 4096]; char master_line[200], srepo[100]; const char *trust;
    long sn = get_seed(seedf, repo, dir, seed, sizeof seed);
    if (sn <= 0 || seed_parse(seed, master_line, sizeof master_line, srepo, sizeof srepo, &trust)) { fprintf(stderr, "取不到或认不出种子(custhub3.seed)\n"); return 1; }
    if (ssh_pub(master_line, G.master)) { fprintf(stderr, "种子里的主公钥不对\n"); return 1; }
    static trust_t t;
    if (mtrust_parse(trust, strlen(trust), &t, G.master)) { fprintf(stderr, "种子名单验签不过\n"); return 1; }
    if (!repo) repo = srepo[0] ? srepo : NULL;

    if (p_self_path(self, sizeof self)) { fprintf(stderr, "找不到本程序的路径\n"); return 1; }
    if (strcmp(self, exe) && copy_file(self, exe)) {
        /* 重复执行: 旧的还在跑(Windows 不让覆盖运行中的程序, 但让改名) → 挪开再放; 下面注册服务时会停掉旧的 */
        char aside[1300]; snprintf(aside, sizeof aside, "%s.old", exe);   /* 和升级用同一个名字: 新版转正时顺手删掉 */
        remove(aside);
        int moved = !p_replace(exe, aside);
        if (!moved) { snprintf(aside, sizeof aside, "%s.old.%lld", exe, (long long)wall_ms()); moved = !p_replace(exe, aside); }   /* .old 也被占着 */
        if (!moved || copy_file(self, exe)) { fprintf(stderr, "装不进 %s(旧的还在跑? 先 custhub remove)\n", exe); return 1; }
        printf("  旧程序还在运行, 挪到 %s\n", aside);
    }
    char how[400];
    if (!getenv("CUSTHUB_HOME") || getenv("CUSTHUB_PATH_DIR")) {
        if (p_path_link(exe, 1, how, sizeof how)) printf("  没能加进 PATH: %s(可以用全路径 %s)\n", how, exe);
        else if (how[0]) printf("  命令: custhub → %s\n", how);
    }

    sep_join(p, sizeof p, node, "node.key");
    if (ident_load(p, &G.id) && ident_new(p, &G.id)) { fprintf(stderr, "生成不了节点钥匙\n"); return 1; }
    /* 名单: 手上没有, 或种子更新, 就用种子的 */
    sep_join(p, sizeof p, node, "trust");
    static char old[MAXTEXT]; static trust_t ot;
    long on = m_read(p, old, sizeof old);
    if (on <= 0 || mtrust_parse(old, (size_t)on, &ot, G.master) || ot.ver < t.ver) m_write(p, trust, strlen(trust));
    else t = ot;                                        /* 手上的更新(比如已经批准过): 按它判断 */
    /* conf: 重写, 只保留本机手动加过的几项 */
    sep_join(p, sizeof p, node, "conf");
    static char oc[8192], nc[8192]; char host[100], logp[1300];
    long ol = m_read(p, oc, sizeof oc);
    p_hostname(host, sizeof host);
    for (char *c = host; *c; c++) if (*c == ' ') *c = '_';
    sep_join(logp, sizeof logp, node, "mesh.log");
    const char *ctl = getenv("CUSTHUB_CTL");           /* 测试用: 本机已经有一份在跑时换个控制口 */
    int n = snprintf(nc, sizeof nc, "master %s\nctl %s\nlog %s\nhello %s %s %s\n", master_line, ctl && *ctl ? ctl : CTL_V3, logp, host, CH_PLAT, CH_VERSION);
    if (repo) n += snprintf(nc + n, sizeof nc - (size_t)n, "github %s\n", repo);
    if (ol > 0) {
        char *sv = NULL;
        for (char *l = m_tok(oc, "\n", &sv); l; l = m_tok(NULL, "\n", &sv))
            if (!strncmp(l, "relay ", 6) || !strncmp(l, "upnp ", 5) || !strncmp(l, "allow ", 6) || !strncmp(l, "listen ", 7) || !strncmp(l, "announce ", 9) || !strncmp(l, "release_base ", 13))
                n += snprintf(nc + n, sizeof nc - (size_t)n, "%s\n", l);
    }
    if (m_write(p, nc, (size_t)n)) { fprintf(stderr, "写不了 %s\n", p); return 1; }
    if (!p_user_mode() && !getenv("CUSTHUB_HOME")) {    /* 本机谁能用: custhub 组的账号不用 root(经本机守护) */
        char gw[200];
        if (p_group_setup(gw, sizeof gw)) printf("  %s(只有 root / 管理员能用 custhub)\n", gw);
        else {
            p_group_share(node, 1); p_group_share(p, 0);
            const char *who = p_invoker();
            if (who && !p_group_user(who, 1, gw, sizeof gw)) printf("  账号 %s 加进了 custhub 组: 重新登录后不用 sudo 就能用 custhub\n", who);
        }
    }

    char why[160];
    printf("  注册系统服务(%s)\n", p_service_kind()); fflush(stdout);
    p_service_remove(node, why, sizeof why);           /* 重复执行: 先把旧的停了 */
    if (p_service_install(exe, node, why, sizeof why)) { fprintf(stderr, "注册服务失败: %s\n", why); return 1; }

    char code[8]; join_code(G.id.ed, code);
    G.quiet = 1;                                        /* 服务刚重启那一两秒连不上本机守护是正常的, 不刷屏 */
    snprintf(G.dir, sizeof G.dir, "%s", node);
    member_t *me = NULL;
    for (int i = 0; i < t.n; i++) if (!memcmp(t.m[i].ed, G.id.ed, 32)) me = &t.m[i];
    if (me) printf("\n本机已在名单里(%s), 不用再批准\n", me->name);
    else printf("\n  接入码: %s\n  请把接入码告诉管理员, 管理员执行: custhub key approve %s <名字>\n", code, code);
    printf("  等待中(最多 %d 秒; 现在关掉也行, 服务会在后台接着等)…\n", wait_s); fflush(stdout);
    char first[400], port[400], lastport[400] = "";
    int64_t end = now_ms() + (int64_t)wait_s * 1000, down_since = now_ms();
    while (now_ms() < end) {
        if (ask_state(node, first, sizeof first, port, sizeof port)) {
            if (now_ms() - down_since > 20000) { fprintf(stderr, "服务没起来(20 秒连不上本机守护), 看 %s\n", logp); return 1; }
            p_sleep_ms(500); continue;
        }
        down_since = now_ms();
        if (port[0] && strcmp(port, lastport) && !strstr(port, "检测中")) { printf("  %s\n", port); fflush(stdout); snprintf(lastport, sizeof lastport, "%s", port); }
        if (!strstr(first, "还没被批准")) {
            char nm[64] = ""; sscanf(first, "本机 %63[^(]", nm);
            printf("\n已接入: 名字 %s\n", nm[0] ? nm : "?");
            return 0;
        }
        p_sleep_ms(1000);
    }
    printf("\n还没批准(接入码 %s)。服务在后台接着等, 批准后自动接入\n", code);
    return 0;
}

/* 服务启动时补上 PATH(老版本装的、升级上来的机器没走过新的 join): 只有本程序就是安装目录里那份时才做 */
void path_ensure(void)
{
    char self[1200], e1[1200], e2[1200], how[400];
    if (getenv("CUSTHUB_HOME") && !getenv("CUSTHUB_PATH_DIR")) return;
    if (p_self_path(self, sizeof self)) return;
    sep_join(e1, sizeof e1, p_install_dir(), exe_name()); sep_join(e2, sizeof e2, p_user_dir(), exe_name());
    if (strcmp(self, e1) && strcmp(self, e2)) return;
    if (!strcmp(self, e2)) p_set_user_mode(1);
    if (p_path_link(self, 1, how, sizeof how)) logf_("没能加进 PATH: %s", how);
    if (p_user_mode()) return;
    char node[1200], conf[1300];                        /* 老版本装的机器: 补上"custhub 组能用"的权限 */
    sep_join(node, sizeof node, p_install_dir(), "node"); sep_join(conf, sizeof conf, node, "conf");
    p_public_dir(p_install_dir()); p_private_dir(node);
    if (!p_group_setup(how, sizeof how)) { p_group_share(node, 1); p_group_share(conf, 0); }
    else logf_("%s", how);
}

/* custhub user add|del <账号> | ls: 本机哪些账号能用 custhub(要 root / 管理员) */
int cmd_user(int argc, char **argv)
{
    char why[300], l[2000];
    if (argc == 1 && !strcmp(argv[0], "ls")) {
        if (p_group_list(l, sizeof l)) { printf("还没有 custhub 组(只有 root / 管理员能用)\n"); return 0; }
        printf("custhub 组(不用 root 就能 sh / connect / ls / pass): %s\n", l[0] ? l : "(没有人)");
        return 0;
    }
    if (argc != 2 || (strcmp(argv[0], "add") && strcmp(argv[0], "del"))) {
        fprintf(stderr, "用法: custhub user add <账号> | del <账号> | ls\n  组里的账号不用 root 就能用本机的通行证开别的机器的 shell: 只加可信的人\n"); return 2;
    }
    int add = !strcmp(argv[0], "add");
    if (p_group_user(argv[1], add, why, sizeof why)) { fprintf(stderr, "%s失败: %s\n", add ? "加入" : "移出", why); return 1; }
    printf(add ? "%s 加进了 custhub 组(重新登录后生效)\n" : "%s 移出了 custhub 组\n", argv[1]);
    return 0;
}

int cmd_run(int argc, char **argv)
{
    char node[1200];
    if (argc > 0) snprintf(node, sizeof node, "%s", argv[0]);
    else snprintf(node, sizeof node, "%s", node_default());
    return mesh_run(node);
}

int cmd_remove3(int argc, char **argv)
{
    if (argc == 1 && !strcmp(argv[0], "--user")) p_set_user_mode(1);
    else if (argc > 0) { fprintf(stderr, "用法: custhub remove [--user]\n"); return 2; }
    if (!p_user_mode() && !p_is_admin() && !getenv("CUSTHUB_HOME")) { fprintf(stderr, "要管理员 / root 权限\n"); return 1; }
    const char *dir = p_install_dir();
    char node[1200], why[160];
    sep_join(node, sizeof node, dir, "node");
    G.quiet = 1;
    int fd = ctl_open_raw(node);                       /* 先让在跑的那份自己退出(Windows 上升级后是新起的进程, 结束任务不一定停得了它) */
    if (fd >= 0) { char b[64]; p_send(fd, "QUIT\n", 5); while (p_recv(fd, b, sizeof b) > 0) {} p_close(fd); }
    p_service_remove(node, why, sizeof why);
    char exe[1200], how[400]; sep_join(exe, sizeof exe, dir, exe_name());
    if (!getenv("CUSTHUB_HOME") || getenv("CUSTHUB_PATH_DIR")) p_path_link(exe, 0, how, sizeof how);
    p_sleep_ms(1500);
    int r = p_rmtree(dir);
    printf(r ? "已注销服务; %s 里有删不掉的, 重启后删\n" : "已注销服务, 删掉了 %s\n", dir);
    return 0;
}
