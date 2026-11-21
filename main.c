/* custhub(v3) 的命令行入口; 测试脚本里本机编的那份叫 ./mesh, 是同一个程序
 *   keygen <目录>              生成节点钥匙 <目录>/node.key(已有就不动), 打印公钥
 *   pub <目录>                 打印公钥
 *   run <目录>                 跑网络守护(读 <目录>/conf、trust)
 *   connect <目录> <名字> <端口> 标准输入输出接到对方本机端口(给 ssh ProxyCommand 用)
 *   ls <目录>                  本机视角的网络状态
 *   ctl <目录> "<一行命令>"     直接对本机网络守护说一句(TRUST / TRUSTPUT / PENDQ, 管理脚本用)
 *   sh <目录> <名字> [-- 命令…]  到对方的 shell(交互, 或跑一条命令、退出码原样带回); 要通行证里有 sh
 *   join --github 仓库 | --seed 文件     接入(装进安装目录、注册服务、报到、显示接入码); remove 卸载
 *   code <目录>                本机接入码
 *   pass <目录> --to … --svc … [--for …] [--hours N] [--out 文件]
 *                              签发通行证(主钥匙在 ssh-agent 里), 见 key.c
 *   passcheck <通行证> <主公钥文件> <用的人公钥> <进哪台|-> <服务|-> <现在(秒)>
 *                              单独考通行证模块: 打印 "ok" 或拒绝原因(测试用) */
#include "mesh.h"
#include "vendor/monocypher-ed25519.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int is_node_dir(const char *d)                    /* 有 conf 或 node.key 的目录 */
{
    char p[1300]; FILE *f;
    snprintf(p, sizeof p, "%s/conf", d); if ((f = fopen(p, "rb"))) { fclose(f); return 1; }
    snprintf(p, sizeof p, "%s/node.key", d); if ((f = fopen(p, "rb"))) { fclose(f); return 1; }
    return 0;
}

int cmd_mesh(int argc, char **argv)
{
    argv = p_args_utf8(argc, argv);
    int JSON = 0;                                        /* --json(除了 exec 自己处理): 给脚本 / AI 的结构化输出 */
    if (argc > 1 && strcmp(argv[1], "exec")) {
        int w = 1;
        for (int r = 1; r < argc; r++) { if (!strcmp(argv[r], "--json")) JSON = 1; else argv[w++] = argv[r]; }
        argc = w; argv[argc] = NULL;
    }
    p_private_files();                                   /* 钥匙、令牌、通行证、日志: 只有自己能读写 */
    const char *c = argc > 1 ? argv[1] : "";
    /* sh / connect / ls / code 的节点目录可以省: 第一个参数不是节点目录就用默认的(用户模式装过就用它) */
    static char *av2[64];
    if (argc >= 2 && argc < 62 && (!strcmp(c, "sh") || !strcmp(c, "connect") || !strcmp(c, "ls") || !strcmp(c, "code") || !strcmp(c, "line") || !strcmp(c, "ping") || !strcmp(c, "netcheck") || !strcmp(c, "bench") || !strcmp(c, "send") || !strcmp(c, "pull") || !strcmp(c, "inventory") || !strcmp(c, "exec") || !strcmp(c, "log") || !strcmp(c, "watch") || !strcmp(c, "wait") || !strcmp(c, "alerts")) &&
        (argc == 2 || !is_node_dir(argv[2]))) {
        av2[0] = argv[0]; av2[1] = argv[1]; av2[2] = (char *)node_default();
        for (int i = 2; i < argc; i++) av2[i + 1] = argv[i];
        argc++; av2[argc] = NULL; argv = av2;
    }
    if (argc == 1 && p_tty_raw(1)) { p_tty_raw(0); return cmd_tui(node_default()); }   /* 不带参数 + 在终端里: 界面 */
    if (argc <= 3 && !strcmp(c, "tui")) return cmd_tui(argc == 3 ? argv[2] : node_default());
    char p[300], b64[48];
    if (argc == 3 && (!strcmp(c, "keygen") || !strcmp(c, "pub"))) {
        if (!strcmp(c, "keygen")) {                      /* 目录没有就建(连上一级), 只给自己 */
            char par[1200]; snprintf(par, sizeof par, "%s", argv[2]);
            char *sl = strrchr(par, '/'), *bs = strrchr(par, '\\'); if (bs > sl) sl = bs;
            if (sl && sl != par) { *sl = 0; p_mkdir(par); }
            p_mkdir(argv[2]); p_private_dir(argv[2]);
        }
        snprintf(p, sizeof p, "%s/node.key", argv[2]);
        int have = ident_load(p, &G.id) == 0;
        if (!have && (strcmp(c, "keygen") || ident_new(p, &G.id))) { fprintf(stderr, "%s 失败\n", p); return 1; }
        b64_encode(G.id.ed, 32, b64);
        printf("%s\n", b64);
        return 0;
    }
    if (argc == 3 && !strcmp(c, "run")) { path_ensure(); return mesh_run(argv[2]); }
    if (argc == 2 && !strcmp(c, "run")) { path_ensure(); return cmd_run(0, argv + 2); }   /* 默认安装目录下的 node */
    if (argc == 3 && !strcmp(c, "ls")) return cmd_ls(argv[2]);
    if (argc == 5 && !strcmp(c, "connect")) return cmd_connect(argv[2], argv[3], argv[4]);
    if (argc == 4 && !strcmp(c, "ctl")) return cmd_ctl(argv[2], argv[3]);
    if (argc == 8 && !strcmp(c, "passcheck")) return cmd_passcheck(argv + 2);
    if (!strcmp(c, "pass")) return cmd_pass_local(argc - 2, argv + 2);
    if (argc == 8 && !strcmp(c, "scrypt")) {             /* 测试用: scrypt 口令 盐 N r p 长度 → 十六进制 */
        uint8_t o[128]; size_t dk = (size_t)atoi(argv[7]);
        if (dk > sizeof o || scrypt_kdf((const uint8_t *)argv[2], strlen(argv[2]), (const uint8_t *)argv[3], strlen(argv[3]),
                                         (uint32_t)atol(argv[4]), atoi(argv[5]), atoi(argv[6]), o, dk)) return 1;
        for (size_t i = 0; i < dk; i++) printf("%02x", o[i]);
        printf("\n"); return 0;
    }
    if (argc == 2 && !strcmp(c, "masterpub")) {          /* 测试用: 环境变量 CUSTHUB_PASSPHRASE 的口令 → 主公钥(同 passkey.py pub) */
        uint8_t seed[32], sk[64], pk[32]; const char *ph = getenv("CUSTHUB_PASSPHRASE");
        if (!ph || passphrase_seed(ph, "ssh", seed)) { fprintf(stderr, "口令不对: 至少 8 个词\n"); return 1; }
        crypto_ed25519_key_pair(sk, pk, seed);
        uint8_t kb[51]; char b[100]; b64_encode(kb, ssh_keyblob(pk, kb), b);
        printf("ssh-ed25519 %s custhub-master\n", b); return 0;
    }
    if (argc == 3 && !strcmp(c, "line")) {               /* 新机器的一行接入命令(问守护: 它知道谁现在可达) */
        static char b[1024]; int fd = ctl_open_raw(argv[2]);
        if (fd < 0 || p_send(fd, "LINE\n", 5) != 5) { fprintf(stderr, "连不上本机守护\n"); return 1; }
        size_t n = 0; long r; while (n < sizeof b - 1 && (r = p_recv(fd, b + n, sizeof b - 1 - n)) > 0) n += (size_t)r;
        p_close(fd); b[n] = 0;
        char *nl = strchr(b, '\n'); if (!nl) { fprintf(stderr, "守护没给(旧版本?)\n"); return 1; }
        *nl = 0; fprintf(stderr, "%s\n", strcmp(b, "-") ? b : "(网里没有可达的 0.3.11 以上的机器, 用 GitHub 的; Win7 用不了)");
        fputs(nl + 1, stdout); return 0;
    }
    if (argc == 4 && !strcmp(c, "ping")) {               /* 到某台的各条链路、延迟、现在走哪条; 每秒一次, 共 4 次(--json 只要一次) */
        char l[120]; snprintf(l, sizeof l, "PING %s%s", argv[3], JSON ? " json" : "");
        if (JSON) return cmd_ctl(argv[2], l);
        for (int k = 0; k < 4; k++) { if (k) { p_sleep_ms(1000); printf("\n"); } if (cmd_ctl(argv[2], l)) return 1; fflush(stdout); }
        return 0;
    }
    if (argc == 3 && !strcmp(c, "netcheck")) return cmd_ctl(argv[2], JSON ? "NETCHECK json" : "NETCHECK");
    if (argc == 4 && !strcmp(c, "netcheck")) return cmd_info(argv[2], argv[3], JSON ? "info:netcheck:json" : "info:netcheck");   /* 看别的机器的 netcheck(只读; 要 info 或 sh 通行证) */
    if (argc >= 3 && !strcmp(c, "log")) {                /* custhub log [名字] [--grep 关键字] [--lines 行数]: 不给名字 = 本机 */
        const char *who = NULL, *key = ""; int lines = 100;
        for (int k = 3; k < argc; k++) {
            if (!strcmp(argv[k], "--grep") && k + 1 < argc) key = argv[++k];
            else if (!strcmp(argv[k], "--lines") && k + 1 < argc) lines = atoi(argv[++k]);
            else if (argv[k][0] != '-' && !who) who = argv[k];
            else { fprintf(stderr, "用法: custhub log [名字] [--grep 关键字] [--lines 行数]\n"); return 2; }
        }
        char ek[200]; size_t el = 0;                     /* 关键字里的空格、% 编码一下(请求按空格分段) */
        for (const char *c2 = key; *c2 && el < sizeof ek - 4; c2++) { if (*c2 == ' ') { memcpy(ek + el, "%20", 3); el += 3; } else if (*c2 == '%') { memcpy(ek + el, "%25", 3); el += 3; } else ek[el++] = *c2; }
        ek[el] = 0;
        char rq[300];
        if (!who) { snprintf(rq, sizeof rq, "LOG %d %s", lines, ek); return cmd_ctl(argv[2], rq); }
        snprintf(rq, sizeof rq, "info:log:%d:%s", lines, ek);
        return cmd_info(argv[2], who, rq);
    }
    if (argc == 3 && !strcmp(c, "inventory")) return cmd_ctl(argv[2], JSON ? "INV json" : "INV");   /* 所有机器的基本信息(系统、机型、版本、能力、本机到它怎么连) */
    if (argc >= 4 && !strcmp(c, "exec")) return cmd_exec(argc - 2, argv + 2);
    if (argc == 4 && !strcmp(c, "alerts")) return cmd_alerts(argv[2], argv[3]);   /* custhub alerts on|off|status */
    if (argc >= 3 && !strcmp(c, "watch")) {              /* custhub watch [--json] [--notify] */
        int nt = 0; for (int k = 3; k < argc; k++) { if (!strcmp(argv[k], "--notify")) nt = 1; else { fprintf(stderr, "用法: custhub watch [--json] [--notify]\n"); return 2; } }
        return cmd_watch(argv[2], JSON, nt);
    }
    if (argc >= 5 && !strcmp(c, "wait")) {               /* custhub wait <名字> <条件> [值] [--timeout 秒] */
        const char *val = NULL; int tmo = 600, k = 5;
        if (k < argc && strcmp(argv[k], "--timeout")) val = argv[k++];
        if (k + 1 < argc && !strcmp(argv[k], "--timeout")) { tmo = atoi(argv[k + 1]); k += 2; }
        if (k != argc || (!strcmp(argv[4], "version") && !val)) { fprintf(stderr, "用法: custhub wait <名字> <online|offline|reachable|direct|version 版本> [--timeout 秒]\n"); return 2; }
        return cmd_wait(argv[2], argv[3], argv[4], val, tmo);
    }
    if (argc == 6 && !strcmp(c, "send")) return cmd_send(argv[2], argv[3], argv[4], argv[5], JSON);   /* custhub send 本机文件 A-2 对方路径 */
    if (argc == 6 && !strcmp(c, "pull")) return cmd_pull(argv[2], argv[3], argv[4], argv[5], JSON);   /* custhub pull 本机路径 A-2 对方文件 */
    if ((argc == 4 || argc == 5) && !strcmp(c, "bench")) {   /* 测速: 上传、下载各测几秒(默认 5), 走平常的流(同样的加密、额度、选路) */
        int secs = argc == 5 ? atoi(argv[4]) : 5; if (secs < 1 || secs > 60) secs = 5;
        char l[120]; snprintf(l, sizeof l, "PING %s", argv[3]);
        if (!JSON && cmd_ctl(argv[2], l)) return 1;
        static uint8_t z[65536]; memset(z, 0, sizeof z);
        int fd = ctl_open(argv[2], argv[3], "bench:up");   /* 上传: 往对方灌, 对方收下就扔 */
        if (fd < 0) return 1;
        int64_t t0 = now_ms(), sent = 0;
        while (now_ms() - t0 < (int64_t)secs * 1000) { long w = p_send(fd, z, sizeof z); if (w <= 0) break; sent += w; }
        double up = sent / ((now_ms() - t0) / 1000.0) / 1048576.0;
        p_close(fd);
        char rq[32]; snprintf(rq, sizeof rq, "bench:dn:%d", secs);
        fd = ctl_open(argv[2], argv[3], rq);               /* 下载: 对方尽力发, 收到底为止 */
        if (fd < 0) return 1;
        int64_t got = 0, t1 = 0; long r;
        while ((r = p_recv(fd, z, sizeof z)) > 0) { if (!t1) t1 = now_ms(); got += r; }
        double dn = t1 ? got / ((now_ms() - t1) / 1000.0 + 0.001) / 1048576.0 : 0;
        p_close(fd);
        if (JSON) printf("{\"name\":\"%s\",\"secs\":%d,\"up_mbps\":%.2f,\"down_mbps\":%.2f,\"up_bytes\":%lld,\"down_bytes\":%lld}\n", argv[3], secs, up, dn, (long long)sent, (long long)got);
        else printf("上传 %.2f MB/s(%lld MB / %d 秒, 含发送缓冲, 略偏高)\n下载 %.2f MB/s(%lld MB)\n", up, (long long)(sent >> 20), secs, dn, (long long)(got >> 20));
        return 0;
    }   /* 本机网络状况: 入站、UPnP、IPv6、打洞、各直连延迟 */
    if (argc == 3 && !strcmp(c, "code")) {               /* 本机接入码 */
        snprintf(p, sizeof p, "%s/node.key", argv[2]);
        char code[8];
        if (ident_load(p, &G.id)) return cmd_ctl(argv[2], "CODE");   /* 钥匙只有 root 能读: 问守护 */
        join_code(G.id.ed, code); printf("%s\n", code); return 0;
    }
    /* 要 root / 管理员的命令: 不是就自己换成 sudo 重跑(会问密码); 用户模式装的(管理电脑)不用 */
    int user_inst = strstr(node_default(), p_user_dir()) == node_default();
    int want_root = !strcmp(c, "join") || !strcmp(c, "remove") || !strcmp(c, "user") || (!strcmp(c, "key") && !user_inst);
    for (int i = 2; i < argc; i++) if (!strcmp(argv[i], "--user") || !strcmp(argv[i], "--dir")) want_root = 0;   /* --dir: 指定了自己的节点目录(测试 / 第一次建网) */
    if (!strcmp(c, "remove") && user_inst) want_root = 0;
    if (want_root && !p_is_admin() && !getenv("CUSTHUB_HOME") && !(argc >= 3 && !strcmp(c, "user") && !strcmp(argv[2], "ls"))) {
        p_elevate(argc, argv);
        fprintf(stderr, "custhub %s 要 root / 管理员权限: %s\n", c, strncmp(CH_PLAT, "win", 3) ? "用 sudo custhub …" : "用\"以管理员身份运行\"的终端");
        return 1;
    }
    if (!strcmp(c, "user")) return cmd_user(argc - 2, argv + 2);
    if (!strcmp(c, "join")) return cmd_join3(argc - 2, argv + 2);
    if (!strcmp(c, "key")) return cmd_key(argc - 2, argv + 2);
    if (!strcmp(c, "remove")) return cmd_remove3(argc - 2, argv + 2);
    if (argc == 2 && !strcmp(c, "version")) { printf("custhub %s %s\n", CH_VERSION, CH_PLAT); return 0; }
    if (argc >= 4 && !strcmp(c, "sh")) return cmd_sh(argc - 2, argv + 2);
    int all = argc >= 3 && !strcmp(c, "help") && !strcmp(argv[2], "all");
    FILE *o = !strcmp(c, "help") ? stdout : stderr;
    fprintf(o, "custhub %s(%s)\n\n"
            "接入 / 卸载\n"
            "  custhub join                      接入网络(装好、注册服务、加进 PATH、显示接入码)\n"
            "  custhub remove                    卸载(服务、PATH、安装目录一起撤)\n\n"
            "日常\n"
            "  custhub ls                        网里有谁、通不通\n"
            "  custhub sh <机器>                 打开对方终端\n"
            "  custhub sh <机器> -- <命令>       在对方跑一条命令, 退出码原样带回\n"
            "  custhub connect <机器> <端口>     接到对方本机端口(可给 ssh 当 ProxyCommand)\n"
            "  custhub pass <文件>               装上别人发给你的通行证\n"
            "  custhub pass                      看本机有哪些通行证、到哪天过期\n\n"
            "本机账号(要 root, 不是 root 会自动 sudo)\n"
            "  custhub user add <账号>           让这个账号不用 root 也能用 custhub(加进 custhub 组)\n"
            "  custhub user del <账号> | ls      移出 / 列出\n\n"
            "管理员(要主钥匙)\n"
            "  custhub key unlock | lock | status         解锁 / 上锁主钥匙\n"
            "  custhub key pending                        待批准的机器(带接入码)\n"
            "  custhub key approve <接入码> <名字>        批准并起名\n"
            "  custhub key remove <名字>                  移出网络\n"
            "  custhub line                               新机器的一行接入命令(从网里一台可达机器 http 下载, Win7 也能装)\n"
            "  custhub ping <名字>                        到这台的各条直连(TCP / UDP)、延迟、现在走哪条\n"
            "  custhub netcheck                           本机网络状况: 入站、UPnP、IPv6、打洞、各直连延迟\n"
            "  custhub send <本机文件> <名字> <对方路径>     发文件过去(对方路径是目录就放进去); 断了再执行一次会续传\n"
            "  custhub pull <本机路径> <名字> <对方文件>     把对方的文件拉过来(本机路径是目录就放进去); 同上\n"
            "  custhub inventory [--json]                  所有机器的基本信息(系统、机型、版本、能力、本机到它怎么连), 不连机器\n"
            "  custhub exec <目标> [--json] [--timeout 秒] -- 命令…   多台并行跑一条命令; 目标: 名字 / A-2,A-7 / @all @online @win @win7 @linux @mac\n"
            "  custhub netcheck <名字>                     看别的机器的网络状况(只读; 要 info 或 sh 通行证)\n"
            "  custhub log [名字] [--grep 关键字] [--lines 行数]   看日志(不给名字 = 本机; 别的机器要 info 或 sh 通行证)\n"
            "  custhub watch [--json] [--notify]           持续看事件(上线、离线、版本、能力、直连); --notify 离线太久、版本卡住、能力变差时弹通知\n"
            "  custhub alerts on|off|status                这台电脑、当前用户: 登录时自动后台看着, 有问题弹通知\n"
            "  custhub wait <名字> <online|offline|reachable|direct|version 版本> [--timeout 秒]   等到条件成立(返回 0), 超时返回 4\n"
            "  custhub bench <名字> [秒]                  到这台的上传 / 下载速度(要有它的 shell 通行证; 默认各 5 秒)\n"
            "  custhub key pass --to <机器,…> [--for <人>] [--svc \"sh file info port:N\"] [--hours 2]\n"
            "                                             签通行证; 不写 --for 是给自己, 直接生效\n"
            "                                             写 --for 时存成 <人>.pass, 发给对方\n\n"
            "其他\n"
            "  custhub                           不带参数: 终端界面(列表、开 shell、通行证; 解锁后批准、签证、新客户接入)\n"
            "  custhub version | code | help [all]\n", CH_VERSION, CH_PLAT);
    if (all) fprintf(o, "\n不常用\n"
            "  custhub join --github 仓库 | --seed 文件 [--user]   指定种子; --user 用户模式(装在家目录, 不要 root)\n"
            "  custhub run [节点目录]                系统服务跑的就是它\n"
            "  custhub keygen <目录> | pub <目录>     生成 / 打印节点钥匙\n"
            "  custhub key ls                         名单\n"
            "  custhub key seed | sign-trust | release …   第一次建网、发版(见 README)\n"
            "  以上命令都可以在最前面写节点目录(测试用), 或 custhub key --dir <目录> …\n");
    return strcmp(c, "help") ? 2 : 0;
}

/* custhub pass [--dir 目录] [文件]: 带文件 = 装上别人发来的通行证; 不带 = 列出本机的。都经本机守护(custhub 组的账号也能用) */
int cmd_pass_local(int argc, char **argv)
{
    const char *dir = NULL, *file = NULL;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--dir") && i + 1 < argc) dir = argv[++i];
        else if (!file && argv[i][0] != '-') file = argv[i];
        else { fprintf(stderr, "用法: custhub pass [文件]\n  带文件: 装上别人发给你的通行证; 不带: 列出本机的通行证\n"
                               "  (给别人签通行证是 custhub key pass)\n"); return 2; }
    }
    if (!dir) dir = node_default();
    static char t[PASSMAX + 1], line[PASSMAX * 2 + 32];
    if (file) {
        long n = m_read(file, t, sizeof t);
        if (n <= 0) { fprintf(stderr, "读不了 %s\n", file); return 1; }
        int k = snprintf(line, sizeof line, "PASSPUT ");
        b64_encode((const uint8_t *)t, (size_t)n, line + k);
    } else snprintf(line, sizeof line, "PASSLS");
    return cmd_ctl(dir, line);
}
int cmd_passcheck(char **a)
{
    static char t[PASSMAX + 2], mk[512];
    static pass_t P;
    uint8_t master[32], who[32], node[32];
    char why[80];
    long n = m_read(a[0], t, sizeof t);
    if (n < 0 || m_read(a[1], mk, sizeof mk) < 0 || ssh_pub(mk, master) ||
        b64_decode(a[2], strlen(a[2]), who, 32) != 32 || (strcmp(a[3], "-") && b64_decode(a[3], strlen(a[3]), node, 32) != 32)) {
        fprintf(stderr, "参数不对\n"); return 2;
    }
    if (pass_parse(t, n < 0 ? 0 : (size_t)n, master, &P, why, sizeof why) ||
        pass_allows(&P, who, strcmp(a[3], "-") ? node : NULL, strcmp(a[4], "-") ? a[4] : NULL, atoll(a[5]), why, sizeof why)) {
        printf("%s\n", why); return 1;
    }
    printf("ok\n");
    return 0;
}
