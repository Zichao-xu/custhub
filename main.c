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
    p_private_files();                                   /* 钥匙、令牌、通行证、日志: 只有自己能读写 */
    const char *c = argc > 1 ? argv[1] : "";
    /* sh / connect / ls / code 的节点目录可以省: 第一个参数不是节点目录就用默认的(用户模式装过就用它) */
    static char *av2[64];
    if (argc >= 2 && argc < 62 && (!strcmp(c, "sh") || !strcmp(c, "connect") || !strcmp(c, "ls") || !strcmp(c, "code")) &&
        (argc == 2 || !is_node_dir(argv[2]))) {
        av2[0] = argv[0]; av2[1] = argv[1]; av2[2] = (char *)node_default();
        for (int i = 2; i < argc; i++) av2[i + 1] = argv[i];
        argc++; av2[argc] = NULL; argv = av2;
    }
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
    if (argc == 3 && !strcmp(c, "run")) return mesh_run(argv[2]);
    if (argc == 2 && !strcmp(c, "run")) return cmd_run(0, argv + 2);   /* 默认安装目录下的 node */
    if (argc == 3 && !strcmp(c, "ls")) return cmd_ls(argv[2]);
    if (argc == 5 && !strcmp(c, "connect")) return cmd_connect(argv[2], argv[3], argv[4]);
    if (argc == 4 && !strcmp(c, "ctl")) return cmd_ctl(argv[2], argv[3]);
    if (argc == 8 && !strcmp(c, "passcheck")) return cmd_passcheck(argv + 2);
    if (argc >= 3 && !strcmp(c, "pass")) return cmd_pass(argc - 2, argv + 2);
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
    if (argc == 3 && !strcmp(c, "code")) {               /* 本机接入码 */
        snprintf(p, sizeof p, "%s/node.key", argv[2]);
        char code[8];
        if (ident_load(p, &G.id)) { fprintf(stderr, "读不了 %s\n", p); return 1; }
        join_code(G.id.ed, code); printf("%s\n", code); return 0;
    }
    if (!strcmp(c, "join")) return cmd_join3(argc - 2, argv + 2);
    if (!strcmp(c, "key")) return cmd_key(argc - 2, argv + 2);
    if (!strcmp(c, "remove")) return cmd_remove3(argc - 2, argv + 2);
    if (argc == 2 && !strcmp(c, "version")) { printf("custhub %s %s\n", CH_VERSION, CH_PLAT); return 0; }
    if (argc >= 4 && !strcmp(c, "sh")) return cmd_sh(argc - 2, argv + 2);
    fprintf(stderr, "custhub %s(%s)\n用法:\n"
            "  custhub join --github 仓库 | --seed 文件     接入(装进安装目录、注册服务、报到、显示接入码)\n"
            "  custhub run [节点目录]                        系统服务跑的就是它\n"
            "  custhub remove                                卸载\n"
            "  custhub sh <目录> <名字> [-- 命令…]           到对方的 shell\n"
            "  custhub connect <目录> <名字> <端口>          标准输入输出接到对方本机端口\n"
            "  custhub ls <目录> | code <目录> | version\n"
            "  custhub key …                                 管理端(解锁、批准、改名单、通行证、种子、发布清单)\n", CH_VERSION, CH_PLAT);
    return 2;
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
