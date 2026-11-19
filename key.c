/* 控制面: 签发通行证(design-v3 §0 第 11 条)。持主钥匙的一方用; 私钥只在 ssh-agent 里, 本程序只问它要一个签名
 *   mesh pass <目录> --to all|名字或公钥,… --svc "sh port:22,3389" [--for 名字|公钥] [--hours N] [--out 文件]
 *     --to    能进哪些机器(名单里的名字, 或节点公钥)
 *     --svc   能用哪些服务: sh  port:*  port:22,3389(空格分开)
 *     --for   发给谁; 不写 = 本机节点自己, 直接写进 <目录>/pass。名单外的机器(访客)只能写公钥
 *     --hours 有效期小时数, 默认 2, 最长 24; 从现在起算(生效时间往前放 1 分钟, 免得对方时钟略快)
 *     --out   写到文件(否则 --for 别人时打印到标准输出)
 *   签完先用通行证模块自己验一遍, 验不过不输出 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int key_of(const char *s, uint8_t out[32], int member_only)
{
    member_t *m = member_by_name(s);
    if (m) { memcpy(out, m->ed, 32); return 0; }
    if (b64_decode(s, strlen(s), out, 32) != 32) return -1;
    return member_only && !member_by_ed(out) ? -1 : 0;
}

static void utc_fmt(int64_t t, char out[24])
{
    time_t tt = (time_t)t;
    struct tm *g = gmtime(&tt);
    if (!g) { snprintf(out, 24, "?"); return; }
    snprintf(out, 24, "%04d-%02d-%02dT%02d:%02d:%02dZ", g->tm_year + 1900, g->tm_mon + 1, g->tm_mday, g->tm_hour, g->tm_min, g->tm_sec);
}

static int ok_svc(const char *s)
{
    char b[200]; snprintf(b, sizeof b, "%s", s);
    char *sv = NULL; int n = 0;
    for (char *t = m_tok(b, " ", &sv); t; t = m_tok(NULL, " ", &sv), n++) {
        if (!strcmp(t, "sh") || !strcmp(t, "port:*")) continue;
        if (strncmp(t, "port:", 5) || !t[5]) return 0;
        for (const char *c = t + 5; *c; c++) if (!((*c >= '0' && *c <= '9') || *c == ',')) return 0;
    }
    return n > 0;
}

int cmd_pass(int argc, char **argv)
{
    const char *dir = NULL, *to = NULL, *svc = "sh", *forw = NULL, *out = NULL; double hours = 2;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--to") && v) { to = v; i++; }
        else if (!strcmp(a, "--svc") && v) { svc = v; i++; }
        else if (!strcmp(a, "--for") && v) { forw = v; i++; }
        else if (!strcmp(a, "--out") && v) { out = v; i++; }
        else if (!strcmp(a, "--hours") && v) { hours = atof(v); i++; }
        else if (!dir && a[0] != '-') dir = a;
        else { dir = NULL; break; }
    }
    if (!dir || !to) {
        fprintf(stderr, "用法: custhub key pass --to all|机器,… [--svc \"sh port:22\"(默认 sh)] [--for 名字|公钥] [--hours N(默认 2)] [--out 文件|-]\n"
                        "  不写 --for: 给本机, 直接生效; 写 --for: 存成 <名字>.pass, 发给对方, 对方 custhub pass <文件> 装上\n");
        return 2;
    }
    G.quiet = 1;
    if (mesh_conf_load(dir)) { fprintf(stderr, "读不了 %s 的节点配置(要有 node.key、conf 里的 master、trust)\n", dir); return 2; }
    if (hours <= 0 || hours > 24) { fprintf(stderr, "--hours 要在 0~24 之间(通行证最长 1 天)\n"); return 2; }
    if (!ok_svc(svc)) { fprintf(stderr, "--svc 不对: 只认 sh、port:*、port:22,3389 这几种写法\n"); return 2; }

    uint8_t who[32]; char whob[48];
    if (!forw) memcpy(who, G.id.ed, 32);
    else if (key_of(forw, who, 0)) { fprintf(stderr, "--for %s: 名单里没有这个名字, 也不是节点公钥\n", forw); return 2; }
    b64_encode(who, 32, whob);

    static char body[PASSMAX], tos[PASSTO * 48 + 8];
    size_t tl = 0; int nto = 0;
    if (!strcmp(to, "all")) tl = (size_t)snprintf(tos, sizeof tos, "all");
    else {
        char b[PASSTO * 48]; snprintf(b, sizeof b, "%s", to);
        char *sv = NULL;
        for (char *t = m_tok(b, ",", &sv); t; t = m_tok(NULL, ",", &sv)) {
            uint8_t k[32]; char kb[48];
            if (++nto > PASSTO) { fprintf(stderr, "--to 最多 %d 台\n", PASSTO); return 2; }
            if (key_of(t, k, 1)) { fprintf(stderr, "--to %s: 名单里没有这台机器\n", t); return 2; }
            b64_encode(k, 32, kb);
            tl += (size_t)snprintf(tos + tl, sizeof tos - tl, "%s%s", tl ? " " : "", kb);
        }
    }
    int64_t now = wall_ms() / 1000, from = now - 60, until = now + (int64_t)(hours * 3600);
    char fs[24], us[24]; utc_fmt(from, fs); utc_fmt(until, us);
    int bl = snprintf(body, sizeof body, "custhub-pass v1\nkey %s\nto %s\nsvc %s\nfrom %s\nuntil %s\n--end--\n", whob, tos, svc, fs, us);

    uint8_t tbs[256], req[512], resp[512], sig[64]; char why[120];
    size_t tn = sshsig_tbs("custhub-pass", (const uint8_t *)body, (size_t)bl, tbs, sizeof tbs);
    size_t rn = agent_sign_req(G.master, tbs, tn, req, sizeof req);
    long an = p_agent_call(req, rn, resp, sizeof resp, why, sizeof why);
    if (an < 0) { fprintf(stderr, "签不了: %s\n", why); return 1; }
    if (agent_sign_resp(resp, (size_t)an, sig)) { fprintf(stderr, "签不了: ssh-agent 里没有主钥匙(先解锁)\n"); return 1; }

    static char text[PASSMAX];
    size_t al = sshsig_armor(G.master, "custhub-pass", sig, text + bl, sizeof text - (size_t)bl);
    if (!al) { fprintf(stderr, "通行证太长\n"); return 1; }
    memcpy(text, body, (size_t)bl);
    size_t len = (size_t)bl + al;

    static pass_t P;
    if (pass_parse(text, len, G.master, &P, why, sizeof why) || pass_allows(&P, who, NULL, NULL, now, why, sizeof why)) {
        fprintf(stderr, "签出来的通行证自己验不过(%s), 不输出\n", why); return 1;
    }
    char path[1300];
    if (!forw && !out) {                                  /* 给本机: 存进本机的通行证位置(几张并存) */
        if (pass_store(text, len, path, sizeof path)) { fprintf(stderr, "存不了: %s\n", path); return 1; }
        fprintf(stderr, "通行证 → 本机(%s): 进 %s, 用 %s, %s 到期\n", path, to, svc, us);
        return 0;
    }
    if (forw && !out) {                                   /* 给别人: 默认存成 <名字>.pass(公钥给的叫 guest-<前 6 位>.pass) */
        int named = member_by_name(forw) != NULL;
        if (named) snprintf(path, sizeof path, "%s.pass", forw);
        else { char sh6[8]; snprintf(sh6, sizeof sh6, "%.6s", whob); for (char *c = sh6; *c; c++) if (*c == '/' || *c == '+') *c = '_';
               snprintf(path, sizeof path, "guest-%s.pass", sh6); }
        out = path;
    }
    if (out && strcmp(out, "-")) {
        if (m_write(out, text, len)) { fprintf(stderr, "写不了 %s\n", out); return 1; }
        fprintf(stderr, "通行证 → %s: 给 %s, 进 %s, 用 %s, %s 到期\n", out, forw ? forw : "本机", to, svc, us);
        if (forw) fprintf(stderr, "  把这个文件发给对方, 对方执行: custhub pass %s\n", out);
    } else fwrite(text, 1, len, stdout);
    return 0;
}

/* ===================== custhub key: 管理端(持主钥匙的一方) =====================
 *   key unlock [小时]        口令 → 主钥匙放进 ssh-agent(默认 8 小时; 派生同 passkey.py, 主钥匙不变)
 *   key lock | status
 *   key pending              各可达节点收到的报到(主钥匙当场签的查询), 带接入码
 *   key approve <接入码> <名字>    批准: 名单加一行 node, 版本 +1, 签名, 交给本机节点沿链路传开
 *   key remove <名字> | ls
 *   key pass …               签通行证(同 mesh pass, 目录默认本机节点)
 *   key seed [--github 仓库] [--out 文件]    种子 custhub3.seed(主公钥 + 仓库 + 当前名单); 第一次建网还没节点时用 --trust 名单 --master 主公钥
 *   key sign-trust <名单正文> [--master 主公钥] [--out 文件]    第一次建网: 签第一份名单
 *   key release <版本> <custhub3-版本-平台 文件>… [--only "名字 …"] [--out 文件]    签发布清单 custhub3.release
 *   共同参数 --dir <节点目录>: 默认安装目录下的 node; 口令可由环境变量 CUSTHUB_PASSPHRASE 给(测试用) */
#include "vendor/monocypher-ed25519.h"

long agent_sshsig(const char *ns, const uint8_t *msg, size_t n, char *armor, size_t cap, char *why, size_t wcap)
{
    uint8_t tbs[256], req[512], resp[512], sig[64];
    size_t tn = sshsig_tbs(ns, msg, n, tbs, sizeof tbs);
    size_t rn = agent_sign_req(G.master, tbs, tn, req, sizeof req);
    long an = p_agent_call(req, rn, resp, sizeof resp, why, wcap);
    if (an < 0) return -1;
    if (agent_sign_resp(resp, (size_t)an, sig)) { snprintf(why, wcap, "ssh-agent 里没有主钥匙(先 custhub key unlock)"); return -1; }
    size_t al = sshsig_armor(G.master, ns, sig, armor, cap);
    if (!al) { snprintf(why, wcap, "签名太长"); return -1; }
    return (long)al;
}

static long ctl_req(const char *dir, const char *line, char *out, size_t cap)   /* 对本机节点说一句, 收全部回答 */
{
    int fd = ctl_open_raw(dir);
    if (fd < 0) return -1;
    size_t l = strlen(line);
    if (p_send(fd, line, l) != (long)l || p_send(fd, "\n", 1) != 1) { p_close(fd); return -1; }
    size_t n = 0; long r;
    while (n < cap - 1 && (r = p_recv(fd, out + n, cap - 1 - n)) > 0) n += (size_t)r;
    p_close(fd);
    out[n] = 0;
    return (long)n;
}

static int name_ok(const char *s)
{
    size_t n = strlen(s);
    if (!n || n > 31) return 0;
    for (; *s; s++) if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '_' || *s == '-')) return 0;
    return 1;
}

void master_line(char *out, size_t cap)
{
    uint8_t kb[51]; char b[100];
    b64_encode(kb, ssh_keyblob(G.master, kb), b);
    snprintf(out, cap, "ssh-ed25519 %s custhub-master", b);
}

/* 名单: 去掉 / 加上一行, 版本 +1, 签名, 交给本机节点 */
static int trust_edit(const char *dir, const char *drop_name, const char *add_line)
{
    static char t[MAXTEXT], body[MAXTEXT], out[MAXTEXT + 2048], why[160];
    char p[600]; snprintf(p, sizeof p, "%s/trust", dir);
    long n = m_read(p, t, sizeof t);
    char *end = n > 0 ? strstr(t, "\n--end--\n") : NULL;
    if (!end) { fprintf(stderr, "读不了本机名单 %s\n", p); return 1; }
    *end = 0;
    char *nl = strchr(t, '\n');
    size_t bl = (size_t)snprintf(body, sizeof body, "custhub-mesh-trust %ld\n", G.trust.ver + 1);
    for (char *l = nl ? nl + 1 : NULL, *nx; l && *l; l = nx) {
        nx = strchr(l, '\n'); if (nx) *nx++ = 0;
        char kind[16], nm[40];
        if (drop_name && sscanf(l, "%15s %39s", kind, nm) == 2 && !strcmp(nm, drop_name)) continue;
        bl += (size_t)snprintf(body + bl, sizeof body - bl, "%s\n", l);
    }
    if (add_line) bl += (size_t)snprintf(body + bl, sizeof body - bl, "%s\n", add_line);
    bl += (size_t)snprintf(body + bl, sizeof body - bl, "--end--\n");
    long al = agent_sshsig("custhub-mesh-trust", (const uint8_t *)body, bl, out + bl, sizeof out - bl, why, sizeof why);
    if (al < 0) { fprintf(stderr, "签不了: %s\n", why); return 1; }
    memcpy(out, body, bl);
    size_t tl = bl + (size_t)al;
    static char b64[(MAXTEXT + 2048) * 4 / 3 + 16], line[(MAXTEXT + 2048) * 4 / 3 + 32], resp[512];
    b64_encode((const uint8_t *)out, tl, b64);
    snprintf(line, sizeof line, "TRUSTPUT %s", b64);
    if (ctl_req(dir, line, resp, sizeof resp) < 0) { fprintf(stderr, "连不上本机节点(%s)\n", dir); return 1; }
    printf("%s", resp);
    return strncmp(resp, "OK", 2) ? 1 : 0;
}

/* 各可达节点的待批准: 每行 "<可达节点> <公钥> <时间> <来源> <自报信息>" */
static long pending_text(const char *dir, char *out, size_t cap)
{
    char q[64], why[160]; static char t[2048], b64[3000], line[3100];
    int ql = snprintf(q, sizeof q, "custhub-mesh-pending %lld\n", (long long)(wall_ms() / 1000));
    long al = agent_sshsig("custhub-mesh-pending", (const uint8_t *)q, (size_t)ql, t + ql, sizeof t - (size_t)ql, why, sizeof why);
    if (al < 0) { fprintf(stderr, "签不了: %s\n", why); return -1; }
    memcpy(t, q, (size_t)ql);
    b64_encode((const uint8_t *)t, (size_t)ql + (size_t)al, b64);
    snprintf(line, sizeof line, "PENDQ %s", b64);
    long n = ctl_req(dir, line, out, cap);
    if (n < 0) fprintf(stderr, "连不上本机节点(%s)\n", dir);
    return n;
}

static int key_unlock(double hours, int no_node)          /* no_node: 还没有节点, 不比对主公钥, 打印推出来的 */
{
    char ph[1024];
    const char *e = getenv("CUSTHUB_PASSPHRASE");
    if (e) snprintf(ph, sizeof ph, "%s", e);
    else if (p_read_secret("口令: ", ph, sizeof ph)) { fprintf(stderr, "没读到口令\n"); return 1; }
    uint8_t seed[32], s2[32], sk[64], pk[32];
    printf("派生主钥匙(要几秒)…\n"); fflush(stdout);
    int r = passphrase_seed(ph, "ssh", seed);
    memset(ph, 0, sizeof ph);
    if (r) { fprintf(stderr, "口令不对: 至少 8 个词\n"); return 1; }
    memcpy(s2, seed, 32);
    crypto_ed25519_key_pair(sk, pk, s2);                  /* 会擦掉 s2 */
    if (no_node) { memcpy(G.master, pk, 32); char ml[200]; master_line(ml, sizeof ml); printf("主公钥(还没有节点, 没比对): %s\n", ml); }
    else if (memcmp(pk, G.master, 32)) { memset(seed, 0, 32); memset(sk, 0, 64); fprintf(stderr, "这个口令推出的主公钥和本机名单的主公钥不一样, 没放进去\n"); return 1; }
    uint8_t req[300], resp[64]; char why[160];
    size_t rn = agent_add_req(seed, pk, "custhub-master", (uint32_t)(hours * 3600), req, sizeof req);
    long an = p_agent_call(req, rn, resp, sizeof resp, why, sizeof why);
    memset(seed, 0, 32); memset(sk, 0, 64); memset(req, 0, sizeof req);
    if (an < 0) { fprintf(stderr, "放不进 ssh-agent: %s\n", why); return 1; }
    if (an < 1 || resp[0] != 6) { fprintf(stderr, "ssh-agent 拒绝了\n"); return 1; }
    printf("已解锁 %g 小时\n", hours);
    return 0;
}

static int key_lock(void)
{
    uint8_t req[128], resp[64]; char why[160];
    size_t rn = agent_remove_req(G.master, req, sizeof req);
    long an = p_agent_call(req, rn, resp, sizeof resp, why, sizeof why);
    if (an < 0) { fprintf(stderr, "连不上 ssh-agent: %s\n", why); return 1; }
    printf(an >= 1 && resp[0] == 6 ? "已上锁\n" : "本来就没解锁\n");
    return 0;
}

static int key_status(void)
{
    uint8_t req[16]; static uint8_t resp[65536]; char why[160];
    size_t rn = agent_list_req(req, sizeof req);
    long an = p_agent_call(req, rn, resp, sizeof resp, why, sizeof why);
    if (an < 0) { printf("未解锁(%s)\n", why); return 1; }
    int on = agent_list_has(resp, (size_t)an, G.master);
    printf(on ? "已解锁\n" : "未解锁\n");
    return on ? 0 : 1;
}

static int key_release(int argc, char **argv)
{
    const char *ver = argc > 0 ? argv[0] : NULL, *only = NULL, *out = NULL;
    static char body[16384], text[20000], why[160];
    if (!ver) { fprintf(stderr, "用法: custhub key release <版本> <custhub3-版本-平台 文件>… [--only \"名字 …\"] [--out 文件]\n"); return 2; }
    size_t bl = (size_t)snprintf(body, sizeof body, "custhub-rel v1\nversion %s\nsigned %lld\n", ver, (long long)(wall_ms() / 1000));
    for (int i = 1; i < argc; i++) if (!strcmp(argv[i], "--only") && i + 1 < argc) only = argv[i + 1];
    if (only) bl += (size_t)snprintf(body + bl, sizeof body - bl, "only %s\n", only);
    int nf = 0;
    char pre[64]; snprintf(pre, sizeof pre, "custhub3-%s-", ver);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--only") || !strcmp(argv[i], "--out") || !strcmp(argv[i], "--master")) { if (!strcmp(argv[i], "--out")) out = argv[i + 1]; i++; continue; }
        const char *b = strrchr(argv[i], '/'); b = b ? b + 1 : argv[i];
        const char *bs = strrchr(b, '\\'); if (bs) b = bs + 1;
        if (strncmp(b, pre, strlen(pre))) { fprintf(stderr, "%s: 文件名要是 %s<平台>[.exe]\n", argv[i], pre); return 2; }
        char plat[40]; snprintf(plat, sizeof plat, "%s", b + strlen(pre));
        size_t pl = strlen(plat); if (pl > 4 && !strcmp(plat + pl - 4, ".exe")) plat[pl - 4] = 0;
        FILE *f = fopen(argv[i], "rb");
        if (!f) { fprintf(stderr, "读不了 %s\n", argv[i]); return 1; }
        crypto_sha512_ctx c; crypto_sha512_init(&c);
        static uint8_t buf[65536]; size_t k; long tot = 0;
        while ((k = fread(buf, 1, sizeof buf, f)) > 0) { crypto_sha512_update(&c, buf, k); tot += (long)k; }
        fclose(f);
        uint8_t h[64]; crypto_sha512_final(&c, h);
        bl += (size_t)snprintf(body + bl, sizeof body - bl, "file %s %ld ", plat, tot);
        for (int j = 0; j < 64; j++) bl += (size_t)snprintf(body + bl, sizeof body - bl, "%02x", h[j]);
        bl += (size_t)snprintf(body + bl, sizeof body - bl, "\n");
        nf++;
    }
    if (!nf) { fprintf(stderr, "没给程序文件\n"); return 2; }
    bl += (size_t)snprintf(body + bl, sizeof body - bl, "--end--\n");
    long al = agent_sshsig("custhub-rel", (const uint8_t *)body, bl, text + bl, sizeof text - bl, why, sizeof why);
    if (al < 0) { fprintf(stderr, "签不了: %s\n", why); return 1; }
    memcpy(text, body, bl);
    if (out) { if (m_write(out, text, bl + (size_t)al)) { fprintf(stderr, "写不了 %s\n", out); return 1; } fprintf(stderr, "发布清单 %s → %s(%d 个平台)\n", ver, out, nf); }
    else fwrite(text, 1, bl + (size_t)al, stdout);
    return 0;
}

/* 自动编号 A-1, A-2 …: 取名单里最大的 A-N 和本机记的(移出过的号不再用)里大的那个 +1 */
#define NUMPFX "A-"
static int next_number(const char *dir)
{
    int mx = 0; char p[1300], t[64];
    for (int i = 0; i < G.trust.n; i++) {
        const char *nm = G.trust.m[i].name; char *e;
        if (!strncmp(nm, NUMPFX, 2)) { long v = strtol(nm + 2, &e, 10); if (!*e && v > mx) mx = (int)v; }
    }
    snprintf(p, sizeof p, "%s/numbers", dir);
    if (m_read(p, t, sizeof t) > 0) { int v = atoi(t); if (v > mx) mx = v; }
    return mx + 1;
}
static void number_used(const char *dir, const char *name)
{
    char *e; if (strncmp(name, NUMPFX, 2)) return;
    long v = strtol(name + 2, &e, 10); if (*e || v <= 0) return;
    char p[1300], t[64]; snprintf(p, sizeof p, "%s/numbers", dir);
    if (m_read(p, t, sizeof t) > 0 && atoi(t) >= v) return;
    int n = snprintf(t, sizeof t, "%ld\n", v); m_write(p, t, (size_t)n);
}
static void host_clean(const char *in, char *out, size_t cap)   /* 机器名备注: 只留字母数字 - _ . */
{
    size_t o = 0;
    for (; *in && o + 1 < cap; in++) if ((*in >= 'a' && *in <= 'z') || (*in >= 'A' && *in <= 'Z') || (*in >= '0' && *in <= '9') || *in == '-' || *in == '_' || *in == '.') out[o++] = *in;
    out[o] = 0;
}

int cmd_key(int argc, char **argv)
{
    char dir[1200] = "";
    int k = 0; char *av[64];
    for (int i = 0; i < argc && k < 63; i++) {
        if (!strcmp(argv[i], "--dir") && i + 1 < argc) { snprintf(dir, sizeof dir, "%s", argv[++i]); continue; }
        av[k++] = argv[i];
    }
    av[k] = NULL;
    if (!dir[0]) snprintf(dir, sizeof dir, "%s", node_default());
    const char *c = k ? av[0] : "";
    if (!strcmp(c, "pass")) {                            /* 同 mesh pass, 目录默认本机节点 */
        char *pv[66]; int pn = 0; pv[pn++] = dir;
        for (int i = 1; i < k; i++) pv[pn++] = av[i];
        return cmd_pass(pn, pv);
    }
    G.quiet = 1;
    /* 第一次建网: 还没有节点也能 unlock / sign-trust / seed(主公钥用 --master 给, 或 unlock 推出来的) */
    const char *mopt = NULL, *topt = NULL;
    for (int i = 1; i + 1 < k; i++) { if (!strcmp(av[i], "--master")) mopt = av[i + 1]; else if (!strcmp(av[i], "--trust")) topt = av[i + 1]; }
    if (mopt && ssh_pub(mopt, G.master)) { fprintf(stderr, "--master 不对(要 \"ssh-ed25519 AAAA…\")\n"); return 2; }
    if (!strcmp(c, "sign-trust") || (!strcmp(c, "seed") && topt)) {
        char ml[200];
        if (!mopt) { char p[1300], t[4096]; snprintf(p, sizeof p, "%s/conf", dir);
                     char *m = m_read(p, t, sizeof t) > 0 ? strstr(t, "master ") : NULL;
                     if (!m || ssh_pub(m + 7, G.master)) { fprintf(stderr, "要 --master \"ssh-ed25519 …\"(或本机节点的 conf 里有 master)\n"); return 2; } }
        master_line(ml, sizeof ml);
        if (!strcmp(c, "sign-trust")) {
            const char *in = k > 1 ? av[1] : NULL, *out = NULL;
            for (int i = 1; i + 1 < k; i++) if (!strcmp(av[i], "--out")) out = av[i + 1];
            static char body[MAXTEXT], text[MAXTEXT + 2048]; char why[160];
            long n = in ? m_read(in, body, sizeof body) : -1;
            if (n <= 0 || strncmp(body, "custhub-mesh-trust ", 19) || n < 9 || strcmp(body + n - 8, "--end--\n")) {
                fprintf(stderr, "用法: custhub key sign-trust <名单正文文件> [--master 主公钥] [--out 文件]\n"
                                "  正文: 第一行 custhub-mesh-trust <版本>, 每行 node <名字> <公钥> [<地址:8444>](带地址 = 种子线索), 最后一行 --end--\n"); return 2; }
            long al = agent_sshsig("custhub-mesh-trust", (const uint8_t *)body, (size_t)n, text + n, sizeof text - (size_t)n, why, sizeof why);
            if (al < 0) { fprintf(stderr, "签不了: %s\n", why); return 1; }
            memcpy(text, body, (size_t)n);
            static trust_t t;
            if (mtrust_parse(text, (size_t)n + (size_t)al, &t, G.master)) { fprintf(stderr, "签出来的名单自己验不过(格式不对? 名字只能字母数字 _ -)\n"); return 1; }
            if (out) { if (m_write(out, text, (size_t)n + (size_t)al)) { fprintf(stderr, "写不了 %s\n", out); return 1; } fprintf(stderr, "名单 v%ld(%d 个成员) → %s\n", t.ver, t.n, out); }
            else fwrite(text, 1, (size_t)n + (size_t)al, stdout);
            return 0;
        }
        static char t[MAXTEXT], s[MAXTEXT + 512]; const char *repo = NULL, *out = NULL;
        for (int i = 1; i + 1 < k; i++) { if (!strcmp(av[i], "--github")) repo = av[i + 1]; else if (!strcmp(av[i], "--out")) out = av[i + 1]; }
        long tn = m_read(topt, t, sizeof t);
        static trust_t tt;
        if (tn <= 0 || mtrust_parse(t, (size_t)tn, &tt, G.master)) { fprintf(stderr, "%s 不是主钥匙签的名单\n", topt); return 1; }
        if (!repo) { fprintf(stderr, "要 --github 仓库\n"); return 2; }
        int n = snprintf(s, sizeof s, "custhub-seed v1\nmaster %s\ngithub %s\n--trust--\n", ml, repo);
        memcpy(s + n, t, (size_t)tn);
        if (out) { if (m_write(out, s, (size_t)n + (size_t)tn)) return 1; fprintf(stderr, "种子 → %s(名单 v%ld)\n", out, tt.ver); }
        else fwrite(s, 1, (size_t)n + (size_t)tn, stdout);
        return 0;
    }
    int agent_only = !strcmp(c, "unlock") || !strcmp(c, "lock") || !strcmp(c, "status");
    if (mopt && (agent_only || !strcmp(c, "release"))) goto loaded;   /* 只要主公钥的: 有 --master 就不用节点 */
    if (!strcmp(c, "unlock") && !mopt) {                 /* 还没有节点: unlock 直接放, 打印推出的主公钥 */
        char p[1300], t[4096]; snprintf(p, sizeof p, "%s/conf", dir);
        if (m_read(p, t, sizeof t) <= 0) return key_unlock(k > 1 ? atof(av[1]) : 8, 1);
    }
    if (mesh_conf_load(dir)) {
        /* 解锁 / 上锁 / 看状态只要 conf 里的主公钥: 名单还没有也行 */
        char p[1300], t[4096]; snprintf(p, sizeof p, "%s/conf", dir);
        char *m = m_read(p, t, sizeof t) > 0 ? strstr(t, "master ") : NULL;
        if (!agent_only || !m || ssh_pub(m + 7, G.master)) { fprintf(stderr, "读不了本机节点 %s(先 custhub join, 或用 --dir 指定)\n", dir); return 2; }
    }
loaded:
    if (!strcmp(c, "unlock")) return key_unlock(k > 1 && av[1][0] != '-' ? atof(av[1]) : 8, 0);
    if (!strcmp(c, "lock")) return key_lock();
    if (!strcmp(c, "status")) return key_status();
    if (!strcmp(c, "release")) return key_release(k - 1, av + 1);
    if (!strcmp(c, "ls")) {
        printf("名单 v%ld(%d 个成员)\n", G.trust.ver, G.trust.n);
        for (int i = 0; i < G.trust.n; i++) {
            char code[8], b[48]; join_code(G.trust.m[i].ed, code); b64_encode(G.trust.m[i].ed, 32, b);
            printf("  %-14s %s  %-18s %s%s%s\n", G.trust.m[i].name, code, G.trust.m[i].host[0] ? G.trust.m[i].host : "-", b, G.trust.m[i].relay ? "  种子 " : "", G.trust.m[i].relay ? G.trust.m[i].addr : "");
        }
        return 0;
    }
    if (!strcmp(c, "seed")) {
        const char *repo = G.github[0] ? G.github : NULL, *out = NULL;
        for (int i = 1; i + 1 < k; i++) { if (!strcmp(av[i], "--github")) repo = av[++i]; else if (!strcmp(av[i], "--out")) out = av[++i]; }
        if (!repo) { fprintf(stderr, "要 --github 仓库(本机 conf 里也没有)\n"); return 2; }
        char ml[200]; master_line(ml, sizeof ml);
        static char s[MAXTEXT + 512];
        int n = snprintf(s, sizeof s, "custhub-seed v1\nmaster %s\ngithub %s\n--trust--\n", ml, repo);
        memcpy(s + n, G.trust.text, G.trust.tlen);
        size_t tl = (size_t)n + G.trust.tlen;
        if (out) { if (m_write(out, s, tl)) { fprintf(stderr, "写不了 %s\n", out); return 1; } fprintf(stderr, "种子 → %s(名单 v%ld)\n", out, G.trust.ver); }
        else fwrite(s, 1, tl, stdout);
        return 0;
    }
    if (!strcmp(c, "pending") || !strcmp(c, "approve")) {
        static char t[65536];
        if (!strcmp(c, "approve") && (k < 2 || k > 3 || (k == 3 && !name_ok(av[2])))) { fprintf(stderr, "用法: custhub key approve <接入码> [名字(字母数字 _ -, 最多 31; 不写 = 自动编号 " NUMPFX "N)]\n"); return 2; }
        if (pending_text(dir, t, sizeof t) < 0) return 1;
        char want[8] = "";
        if (k >= 2) { for (int i = 0, o = 0; av[1][i] && o < 7; i++) { char ch = av[1][i]; if (ch == '-') continue; if (ch >= 'a' && ch <= 'z') ch -= 32; want[o++] = ch; if (o == 3) want[o++] = '-'; } }
        char hit[48] = "", hhost[64] = ""; int shown = 0;
        char *sv = NULL;
        for (char *l = m_tok(t, "\n", &sv); l; l = m_tok(NULL, "\n", &sv)) {
            char rly[40], edb[64], ts[24], from[80], info[300] = "";
            if (sscanf(l, "%39s %63s %23s %79s %299[^\n]", rly, edb, ts, from, info) < 4) { if (l[0] == '#') fprintf(stderr, "%s\n", l); continue; }
            uint8_t ed[32]; char code[8];
            if (b64_decode(edb, strlen(edb), ed, 32) != 32 || member_by_ed(ed)) continue;
            join_code(ed, code);
            if (!strcmp(c, "pending")) { printf("  %s  %s  来自 %s(经 %s)  %s\n", code, edb, from, rly, info); shown++; }
            else if (!strcmp(code, want)) { snprintf(hit, sizeof hit, "%s", edb); char h0[64] = ""; sscanf(info, "%63s", h0); host_clean(h0, hhost, sizeof hhost); }
        }
        if (!strcmp(c, "pending")) { if (!shown) printf("没有待批准的\n"); return 0; }
        if (!hit[0]) { fprintf(stderr, "待批准里没有接入码 %s 的机器(custhub key pending 看看)\n", want); return 1; }
        char nm[40];
        if (k == 3) snprintf(nm, sizeof nm, "%s", av[2]); else snprintf(nm, sizeof nm, NUMPFX "%d", next_number(dir));
        if (member_by_name(nm)) { fprintf(stderr, "名字 %s 已经有人用了\n", nm); return 1; }
        char line[200]; int ll = snprintf(line, sizeof line, "node %s %s", nm, hit);
        if (hhost[0]) snprintf(line + ll, sizeof line - (size_t)ll, " host=%s", hhost);
        int r = trust_edit(dir, NULL, line);
        if (!r) { number_used(dir, nm); printf("已批准 %s(接入码 %s%s%s), 新名单正沿链路传开\n", nm, want, hhost[0] ? ", 机器名 " : "", hhost); }
        return r;
    }
    if (!strcmp(c, "rename")) {                          /* 改名: 公钥、地址、机器名备注都不变 */
        if (k != 3 || !member_by_name(av[1]) || !name_ok(av[2])) { fprintf(stderr, "用法: custhub key rename <名单里的名字> <新名字(字母数字 _ -, 最多 31)>\n"); return 2; }
        if (member_by_name(av[2])) { fprintf(stderr, "名字 %s 已经有人用了\n", av[2]); return 1; }
        member_t *m = member_by_name(av[1]);
        char kb[48], line[240]; b64_encode(m->ed, 32, kb);
        int ll = snprintf(line, sizeof line, "%s %s %s", "node", av[2], kb);
        if (m->relay && m->addr[0]) ll += snprintf(line + ll, sizeof line - (size_t)ll, " %s", m->addr);
        if (m->host[0]) snprintf(line + ll, sizeof line - (size_t)ll, " host=%s", m->host);
        int r = trust_edit(dir, av[1], line);
        if (!r) { number_used(dir, av[2]); printf("%s 改名为 %s\n", av[1], av[2]); }
        return r;
    }
    if (!strcmp(c, "remove")) {
        if (k != 2 || !member_by_name(av[1])) { fprintf(stderr, "用法: custhub key remove <名单里的名字>\n"); return 2; }
        return trust_edit(dir, av[1], NULL);
    }
    fprintf(stderr, "用法: custhub key unlock [小时] | lock | status | pending | approve <接入码> [名字] | rename <名字> <新名字> | remove <名字> | ls\n"
                    "                  | pass … | seed [--github 仓库] [--trust 名单 --master 主公钥] [--out 文件]\n"
                    "                  | sign-trust <名单正文> [--master 主公钥] [--out 文件] | release <版本> <文件>… [--only …] [--out 文件]   [--dir 节点目录]\n");
    return 2;
}
