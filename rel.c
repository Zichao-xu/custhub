/* 发布物(design-v3 §0 第 15、16 条): 每台自己去 GitHub 拉, 网内有就先从网内取; 换上后试用, 连不上网络就回滚
 *
 * 0.3 线的发布物(GitHub Release 的附件; 0.2.x 的机器看不到这些名字):
 *   custhub3.release              清单, 格式同成员名单: 正文以 --end-- 结束, 后接主钥匙签名(命名空间 custhub-rel)
 *     custhub-rel v1
 *     version 0.3.0
 *     signed <秒>
 *     only <名字或节点公钥> …        可选: 灰度, 只给列出的节点
 *     file <平台> <字节数> <sha512 十六进制>
 *     --end--
 *   custhub3-<版本>-<平台>[.exe]   各平台程序
 * 来源: 位置记录里报了更新版本的成员(可达节点优先, 经 pkg 服务整包取、断点续传) → GitHub 直连 → ghfast → gh-proxy
 *   包和清单靠签名 + sha512 把关, 从谁那里拿都一样; 取包(pkg)免通行证, 只对名单成员开
 *   可达节点顺带缓存清单里所有平台的包, 当种子
 * 节点目录里的文件: rel.release(手上最新的已验清单)  rel-<附件名>(手上的包, 给别人取)  rel-<附件名>.part(下载中)
 *   程序旁边: .new / .old / .bad; 目录里 upgrade.pending("旧版本 新版本 启动次数") 和 upgrade.bad("版本 回滚次数") */
#include "mesh.h"
#include "vendor/monocypher.h"
#include "vendor/monocypher-ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RNS     "custhub-rel"
#define RELMAX  (64 * 1024)
#define BINMAX  (32L * 1024 * 1024)
#define MAXF    24
#define MAXSRC  10

int sshsig_verify(const char *armored, const uint8_t *msg, size_t mlen, const char *ns, uint8_t (*keys)[32], int nkeys);

typedef struct { char plat[32]; long size; uint8_t sha[64]; } relf_t;
typedef struct { char ver[16]; long long signed_at; int nf, gray, me; relf_t f[MAXF]; } rel_t;

/* 一次取一个附件: 依次试各来源, 直到有一个拿到并通过校验 */
typedef struct {
    int active, is_manifest;
    char asset[96], dst[400];               /* dst: 最后放哪(rel-<附件名> 或 rel.release) */
    relf_t want;                            /* 包: 要的大小 + sha512 */
    int nsrc, si;
    struct { int peer; uint8_t ed[32]; char url[300]; } src[MAXSRC];
    int fh;                                 /* 正在用的 http 下载句柄, -1 没有 */
    int sock, got_ok;                       /* 正在用的网内流(本地这头), -1 没有 */
    FILE *part; long have;
    int64_t started;
} job_t;

static int man_fail;                                     /* 发布清单连续取不到的次数(只记第一次) */

static rel_t R;                             /* 手上最新的已验清单 */
static job_t J = { .fh = -1, .sock = -1 };
static int64_t next_check, trial_ms;
static int in_trial;
static char *const *RARGV;

static int64_t env_s(const char *k, long def)
{
    const char *e = getenv(k);
    long v = e ? atol(e) : 0;
    return (v > 0 ? v : def) * (int64_t)1000;
}

long ver_cmp(const char *a, const char *b)
{
    int x[3] = { 0 }, y[3] = { 0 };
    sscanf(a, "%d.%d.%d", &x[0], &x[1], &x[2]); sscanf(b, "%d.%d.%d", &y[0], &y[1], &y[2]);
    for (int i = 0; i < 3; i++) if (x[i] != y[i]) return x[i] - y[i];
    return 0;
}

void rel_set_args(char *const *argv) { RARGV = argv; }

static void path_in(char *out, size_t cap, const char *name) { snprintf(out, cap, "%s/%s", G.dir, name); }

static void asset_of(const char *ver, const char *plat, char *out, size_t cap)
{
    snprintf(out, cap, "custhub3-%s-%s%s", ver, plat, strncmp(plat, "win", 3) ? "" : ".exe");
}

static int hex64(const char *s, uint8_t o[64])
{
    if (strlen(s) != 128) return -1;
    for (int i = 0; i < 64; i++) { unsigned v; if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1; o[i] = (uint8_t)v; }
    return 0;
}

static int rel_parse(const char *text, size_t len, rel_t *r)
{
    static char b[RELMAX + 1];
    if (len > RELMAX || len < 20) return -1;
    memcpy(b, text, len); b[len] = 0;
    if (strncmp(b, RNS " v1\n", strlen(RNS) + 4)) return -1;
    char *end = strstr(b, "\n--end--\n");
    if (!end) return -1;
    size_t dlen = (size_t)(end - b) + 9;
    uint8_t mk[1][32]; memcpy(mk[0], G.master, 32);
    if (!sshsig_verify(b + dlen, (const uint8_t *)b, dlen, RNS, mk, 1)) return -1;
    b[dlen] = 0;
    memset(r, 0, sizeof *r);
    char me_b64[48]; b64_encode(G.id.ed, 32, me_b64);
    char *sv = NULL;
    for (char *l = m_tok(b, "\n", &sv); l; l = m_tok(NULL, "\n", &sv)) {
        char k[16] = "", a[130] = "", c[40] = "", d[160] = "";
        int n = sscanf(l, "%15s %129s %39s %159s", k, a, c, d);
        if (!strcmp(k, "version") && n >= 2 && strlen(a) < sizeof r->ver) snprintf(r->ver, sizeof r->ver, "%s", a);
        else if (!strcmp(k, "signed") && n >= 2) r->signed_at = atoll(a);
        else if (!strcmp(k, "only")) {
            r->gray = 1;
            char *s2 = NULL;
            for (char *t = m_tok(l + 5, " ", &s2); t; t = m_tok(NULL, " ", &s2))
                if ((G.name[0] && !strcmp(t, G.name)) || !strcmp(t, me_b64)) r->me = 1;
        }
        else if (!strcmp(k, "file") && n == 4 && r->nf < MAXF) {
            relf_t *f = &r->f[r->nf];
            snprintf(f->plat, sizeof f->plat, "%s", a);
            f->size = atol(c);
            if (f->size <= 0 || f->size > BINMAX || hex64(d, f->sha)) return -1;
            r->nf++;
        }
    }
    return r->ver[0] && r->nf ? 0 : -1;
}

static relf_t *my_file(rel_t *r)
{
    for (int i = 0; i < r->nf; i++) if (!strcmp(r->f[i].plat, CH_PLAT)) return &r->f[i];
    return NULL;
}

static int bad_count(const char *ver)
{
    char p[400], t[2048]; path_in(p, sizeof p, "upgrade.bad");
    if (m_read(p, t, sizeof t) <= 0) return 0;
    char v[32]; int n = 0, off = 0, k;
    while (sscanf(t + off, "%31s %d%n", v, &n, &k) == 2) { if (!strcmp(v, ver)) return n; off += k; }
    return 0;
}

static void bad_add(const char *ver)
{
    char p[400], o[2048]; int n = bad_count(ver) + 1;
    path_in(p, sizeof p, "upgrade.bad");
    snprintf(o, sizeof o, "%s %d\n", ver, n);
    m_write(p, o, strlen(o));
}

/* ---------- 来源 ---------- */
static void add_peer_sources(job_t *j, const char *need_ver)
{
    for (int pass = 0; pass < 2; pass++)                 /* 先可达节点, 后普通成员 */
        for (int i = 0; i < G.nr && j->nsrc < MAXSRC - 3; i++) {
            rec_t *r = &G.r[i];
            if (ver_cmp(r->ver, need_ver) < 0 || !member_by_ed(r->ed) || (pass == 0) != (ed_relay(r->ed) != 0)) continue;
            j->src[j->nsrc].peer = 1; memcpy(j->src[j->nsrc].ed, r->ed, 32); j->nsrc++;
        }
}

static void add_web_sources(job_t *j, const char *ver)
{
    const char *base = getenv("CUSTHUB_REL_URL");          /* 测试: 指到假 GitHub */
    if (!base && G.relbase[0]) base = G.relbase;           /* conf release_base: 自建发布源 / 镜像 */
    if (base) { j->src[j->nsrc].peer = 0; snprintf(j->src[j->nsrc++].url, sizeof j->src[0].url, "%s%s", base, j->asset); return; }
    if (!G.github[0]) return;
    static const char *pre[] = { "", "https://ghfast.top/", "https://gh-proxy.com/" };
    for (int k = 0; k < 3 && j->nsrc < MAXSRC; k++) {
        if (j->is_manifest) snprintf(j->src[j->nsrc].url, sizeof j->src[0].url, "%shttps://github.com/%s/releases/latest/download/%s", pre[k], G.github, j->asset);
        else snprintf(j->src[j->nsrc].url, sizeof j->src[0].url, "%shttps://github.com/%s/releases/download/v%s/%s", pre[k], G.github, ver, j->asset);
        j->src[j->nsrc++].peer = 0;
    }
}

static void job_stop_src(void)
{
    if (J.fh >= 0) { p_fetch_kill(J.fh); J.fh = -1; }
    if (J.sock >= 0) { p_close(J.sock); J.sock = -1; }
    if (J.part) { fclose(J.part); J.part = NULL; }
}

static void job_try(void);

static void job_begin(int is_manifest, const char *asset, const char *dst, const relf_t *want, const char *ver)
{
    job_stop_src();
    memset(&J, 0, sizeof J); J.fh = J.sock = -1;
    J.active = 1; J.is_manifest = is_manifest; J.started = now_ms();
    snprintf(J.asset, sizeof J.asset, "%s", asset);
    snprintf(J.dst, sizeof J.dst, "%s", dst);
    if (want) J.want = *want;
    add_peer_sources(&J, ver);
    add_web_sources(&J, ver);
    job_try();
}

static void job_done(int ok);

static void job_try(void)
{
    char part[420];
    snprintf(part, sizeof part, "%s.part", J.dst);
    while (J.si < J.nsrc) {
        if (J.src[J.si].peer) {
            int fd[2];
            FILE *f = fopen(part, "ab");               /* 网内取: 接着已有的往下(断点续传) */
            if (!f) { J.si++; continue; }
            fseek(f, 0, SEEK_END); J.have = ftell(f);
            if (J.is_manifest) { fclose(f); remove(part); f = fopen(part, "wb"); J.have = 0; if (!f) { J.si++; continue; } }
            if (p_pair(fd)) { fclose(f); J.si++; continue; }
            char req[160]; snprintf(req, sizeof req, "pkg:%s:%ld", J.asset, J.have);
            if (hop_open_local(fd[0], J.src[J.si].ed, req)) { p_close(fd[0]); p_close(fd[1]); fclose(f); J.si++; continue; }
            J.part = f; J.sock = fd[1]; J.got_ok = 0;
            if (!J.is_manifest) logf_("取 %s: 问 %s(从 %ld 字节起)", J.asset, name_of(J.src[J.si].ed), J.have);   /* 清单 30 秒问一次, 不记 */
            return;
        }
        remove(part);
        J.fh = p_fetch_start(J.src[J.si].url, part);
        if (J.fh >= 0) { if (!J.is_manifest) logf_("取 %s: %s", J.asset, J.src[J.si].url); return; }
        J.si++;
    }
    if (!J.is_manifest || !man_fail++) logf_("取 %s: 所有来源都不行%s", J.asset, J.is_manifest ? "(之后连不上不再记, 连上了再说)" : "");
    job_done(0);
}

static int job_verify(const char *part)
{
    static char t[RELMAX + 1];
    if (J.is_manifest) {
        long n = m_read(part, t, sizeof t);
        rel_t r;
        if (n <= 0 || rel_parse(t, (size_t)n, &r)) return -1;
        /* 只收比手上新的: 版本更高, 或同一版本重新签发(比如修了 sha512); 不够新就换下一个来源 */
        if (R.ver[0] && (ver_cmp(r.ver, R.ver) < 0 || (!ver_cmp(r.ver, R.ver) && r.signed_at <= R.signed_at))) return -1;
        return 0;
    }
    FILE *f = fopen(part, "rb");
    if (!f) return -1;
    crypto_sha512_ctx c; crypto_sha512_init(&c);
    static uint8_t b[65536]; size_t k; long tot = 0;
    while ((k = fread(b, 1, sizeof b, f)) > 0) { crypto_sha512_update(&c, b, k); tot += (long)k; }
    fclose(f);
    uint8_t h[64]; crypto_sha512_final(&c, h);
    return tot == J.want.size && !crypto_verify64(h, J.want.sha) ? 0 : -1;
}

static void src_finished(int ok)                        /* 当前来源结束: ok = 数据收完了 */
{
    char part[420]; snprintf(part, sizeof part, "%s.part", J.dst);
    job_stop_src();
    if (ok && !job_verify(part) && !p_replace(part, J.dst)) { job_done(1); return; }
    if (ok) { logf_("取 %s: 校验没过, 换下一个来源", J.asset); remove(part); }
    J.si++;
    job_try();
}

/* ---------- 网内取的本地一头 ---------- */
void rel_poll_add(pfd_t *p, int *np, int *map)
{
    if (J.sock >= 0) { p[*np].fd = J.sock; p[*np].ev = P_IN; map[(*np)++] = 4000; }
}

void rel_io(int code, short rev)
{
    (void)code;
    if (J.sock < 0 || !(rev & (P_IN | P_HUP))) return;
    static uint8_t b[65536];
    long r = p_recv(J.sock, b, sizeof b);
    if (r == P_AGAIN) return;
    if (r <= 0) { src_finished(J.got_ok); return; }
    size_t off = 0;
    if (!J.got_ok) {                                     /* 连通层先回一行 OK / ERR */
        if (r < 3 || memcmp(b, "OK\n", 3)) { logf_("取 %s: %s 没给(%.*s)", J.asset, name_of(J.src[J.si].ed), (int)(r > 80 ? 80 : r), (char *)b); src_finished(0); return; }
        J.got_ok = 1; off = 3;
    }
    if (r > (long)off && fwrite(b + off, 1, (size_t)r - off, J.part) != (size_t)r - off) { src_finished(0); return; }
    J.have += r - (long)off;
    if (!J.is_manifest && J.have > J.want.size) src_finished(0);
}

/* ---------- 升级流程 ---------- */
static void self_paths(char *cur, char *nw, char *old, char *bad, size_t cap)
{
    if (p_self_path(cur, cap)) cur[0] = 0;
    snprintf(nw, cap, "%s.new", cur); snprintf(old, cap, "%s.old", cur); snprintf(bad, cap, "%s.bad", cur);
}

static void restart(const char *exe)
{
    if (!RARGV) { logf_("不知道怎么重启自己(没有命令行), 退出等服务管理器拉起"); exit(3); }
    const char *av[16]; int n = 0;
    av[n++] = exe;
    for (int i = 1; RARGV[i] && n < 15; i++) av[n++] = RARGV[i];
    av[n] = NULL;
    p_exec_self(exe, av);
    logf_("重启进 %s 失败", exe);
}

static void pending_write(const char *from, const char *to, int tries)
{
    char p[400], o[100]; path_in(p, sizeof p, "upgrade.pending");
    snprintf(o, sizeof o, "%s %s %d\n", from, to, tries);
    m_write(p, o, strlen(o));
}

static int pending_read(char *from, char *to, int *tries)
{
    char p[400], t[100]; path_in(p, sizeof p, "upgrade.pending");
    if (m_read(p, t, sizeof t) <= 0) return 0;
    return sscanf(t, "%31s %31s %d", from, to, tries) == 3;
}

static void pending_clear(void) { char p[400]; path_in(p, sizeof p, "upgrade.pending"); remove(p); }

static void rollback(const char *from, const char *to, const char *why)
{
    char cur[400], nw[420], old[420], bad[420];
    self_paths(cur, nw, old, bad, sizeof cur);
    bad_add(to); pending_clear(); in_trial = 0;
    remove(bad);
    if (p_replace(cur, bad) || p_replace(old, cur)) { logf_("回滚改名失败(%s → %s)", to, from); return; }
    logf_("回滚 %s → %s: %s", to, from, why);
    restart(cur);
}

static void swap_in(const char *pkg, const char *ver)
{
    char cur[400], nw[420], old[420], bad[420], out[200], expect[64];
    self_paths(cur, nw, old, bad, sizeof cur);
    if (!cur[0]) { logf_("找不到本程序的路径, 不升级"); return; }
    /* 先复制一份到 .new, 跑一下核对版本(rel-<附件名> 留着给别人取) */
    FILE *a = fopen(pkg, "rb"), *b = fopen(nw, "wb");
    static uint8_t buf[65536]; size_t k; int ok = a && b;
    while (ok && (k = fread(buf, 1, sizeof buf, a)) > 0) ok = fwrite(buf, 1, k, b) == k;
    if (a) fclose(a);
    if (b && fclose(b)) ok = 0;
    if (!ok) { remove(nw); logf_("复制新版失败"); return; }
    p_make_exec(nw);
    const char *av[] = { nw, "version", NULL };
    snprintf(expect, sizeof expect, "custhub %s ", ver);
    if (p_run(av, out, sizeof out, 20) != 0 || strncmp(out, expect, strlen(expect))) {
        remove(nw); bad_add(ver); logf_("新版 %s 跑不起来或报的版本不对(%.60s), 不升", ver, out); return;
    }
    remove(old);
    FILE *ex = fopen(old, "rb");                         /* 删不掉: 还被别的进程占着(Windows 上残留的旧进程); 运行中的程序能改名, 挪开它 */
    if (ex) { fclose(ex); char st[460]; snprintf(st, sizeof st, "%s.%lld", old, (long long)wall_ms()); if (!p_replace(old, st)) logf_("旧版 %s 还被占着, 挪到 %s", old, st); }
    if (p_replace(cur, old)) { remove(nw); logf_("换下旧版失败"); return; }
    if (p_replace(nw, cur)) { p_replace(old, cur); logf_("换上新版失败"); return; }
    pending_write(CH_VERSION, ver, 0);
    logf_("已换上 %s(原 %s), 重启进新版试用", ver, CH_VERSION);
    restart(cur);
    pending_clear(); p_replace(cur, nw); p_replace(old, cur);   /* 没能重启: 换回去 */
}

static void after_manifest(void);

/* 只留最新版: 清单换到新版本时删掉旧版本的包(启动时把更早攒下的也扫一遍) */
static void drop_ver(const rel_t *r, const char *ver)
{
    char asset[96], n[120], p[400], pp[420];
    for (int i = 0; i < r->nf; i++) {
        asset_of(ver, r->f[i].plat, asset, sizeof asset);
        snprintf(n, sizeof n, "rel-%s", asset); path_in(p, sizeof p, n);
        snprintf(pp, sizeof pp, "%s.part", p);
        remove(p); remove(pp);
    }
}

static void drop_older(void)
{
    int x = 0, y = 0, z = 0;
    if (!R.ver[0] || sscanf(R.ver, "%d.%d.%d", &x, &y, &z) != 3) return;
    char v[32];
    for (int b = y > 0 ? y - 1 : 0; b <= y; b++)
        for (int c = 0; c < (b == y ? z : 100); c++) { snprintf(v, sizeof v, "%d.%d.%d", x, b, c); drop_ver(&R, v); }
}

static void next_pkg(void)                               /* 本机平台先; 再把清单里其他平台、源码、接入脚本都缓存上(给别人取, 也给 HTTP 发) */
{
    char asset[96], dst[400], p[400];
    relf_t *mine = my_file(&R);
    int want_up = ver_cmp(R.ver, CH_VERSION) > 0 && bad_count(R.ver) < 2 && (!R.gray || R.me);
    for (int pass = 0; pass < 2; pass++)
        for (int i = 0; i < R.nf; i++) {
            relf_t *f = &R.f[i];
            if (pass == 0 && (f != mine || !want_up)) continue;
            if (pass == 1 && f == mine && want_up) continue;   /* 不升的(灰度不含本机等)也把本平台的新包缓存上, 给别人 */
            asset_of(R.ver, f->plat, asset, sizeof asset);
            snprintf(p, sizeof p, "rel-%s", asset); path_in(dst, sizeof dst, p);
            FILE *t = fopen(dst, "rb");
            if (t) {
                fclose(t);
                if (pass == 0) { swap_in(dst, R.ver); return; }
                continue;
            }
            job_begin(0, asset, dst, f, R.ver);
            return;
        }
}

static void job_done(int ok)
{
    int was_manifest = J.is_manifest;
    char asset[96]; snprintf(asset, sizeof asset, "%s", J.asset);
    J.active = 0;
    if (!ok) { if (was_manifest && R.ver[0]) next_pkg(); return; }   /* 没有更新的清单: 照手上的再看一遍(可达节点补缓存) */
    if (was_manifest) { after_manifest(); return; }
    logf_("取到 %s, 校验通过", asset);
    next_pkg();
}

static void load_manifest(void)
{
    char p[400]; static char t[RELMAX + 1];
    path_in(p, sizeof p, "rel.release");
    long n = m_read(p, t, sizeof t);
    rel_t r;
    if (n > 0 && !rel_parse(t, (size_t)n, &r)) R = r;
}

static void after_manifest(void)
{
    rel_t old = R;
    load_manifest();
    if (man_fail) { logf_("又取到发布清单了"); man_fail = 0; }
    if (old.ver[0] && ver_cmp(R.ver, old.ver) > 0) drop_ver(&old, old.ver);
    if (!old.ver[0] || ver_cmp(R.ver, old.ver) > 0) {     /* 清单变了才记 */
        logf_("发布清单 %s(本机 %s)", R.ver, CH_VERSION);
        if (R.gray && !R.me && ver_cmp(R.ver, CH_VERSION) > 0) logf_("%s 是灰度版本, 不含本机, 不升", R.ver);
        if (!my_file(&R) && ver_cmp(R.ver, CH_VERSION) > 0) logf_("%s 没有本平台(%s)的包", R.ver, CH_PLAT);
    }
    next_pkg();
}

static void check_now(void)
{
    char dst[400], need[16] = "9999.0.0";              /* 网内没人比本机新: 只问 GitHub */
    const char *have = R.ver[0] && ver_cmp(R.ver, CH_VERSION) > 0 ? R.ver : CH_VERSION;
    for (int i = 0; i < G.nr; i++)                     /* 网内有人报了更新的版本: 先问它们 */
        if (member_by_ed(G.r[i].ed) && ver_cmp(G.r[i].ver, have) > 0 && (!strcmp(need, "9999.0.0") || ver_cmp(G.r[i].ver, need) < 0))
            snprintf(need, sizeof need, "%s", G.r[i].ver);
    path_in(dst, sizeof dst, "rel.release");
    job_begin(1, "custhub3.release", dst, NULL, need);
}

void rel_saw(const char *ver)                            /* 位置记录里看到别人的版本 */
{
    if (ver_cmp(ver, CH_VERSION) > 0 && (!R.ver[0] || ver_cmp(ver, R.ver) > 0) && !J.active) {
        int64_t soon = now_ms() + 3000;
        if (next_check > soon) next_check = soon;
    }
}

int rel_successor(void)                                  /* 本进程是不是升级后接班试用的那份(启动时用: 要等上一份让出端口) */
{
    char from[32], to[32]; int tries;
    return pending_read(from, to, &tries) && !strcmp(to, CH_VERSION);
}

void rel_start(void)
{
    load_manifest();
    drop_older();
    char from[32], to[32]; int tries;
    next_check = now_ms() + env_s("CUSTHUB_REL_FIRST_S", 20);
    if (!pending_read(from, to, &tries)) return;
    if (strcmp(to, CH_VERSION)) { pending_clear(); return; }   /* 跑的不是试用的那个版本 */
    if (++tries > 3) { rollback(from, to, "连续 3 次启动都没转正"); return; }
    pending_write(from, to, tries);
    in_trial = 1; trial_ms = now_ms();
    logf_("试用 %s(第 %d 次启动, 原 %s)", to, tries, from);
}

void rel_tick(void)
{
    int64_t now = now_ms();
    if (in_trial) {
        int up = 0;
        for (int i = 0; i < MAXC; i++) if (G.c[i].state == C_UP && !G.c[i].closing && !G.c[i].probe_for && G.c[i].pm) up = 1;
        char from[32], to[32]; int tries;
        if (!pending_read(from, to, &tries)) in_trial = 0;
        else if (up) {
            pending_clear(); in_trial = 0; logf_("%s 转正(已连上网络)", to);
            char cur[400], nw[420], old[420], bad[420]; self_paths(cur, nw, old, bad, sizeof cur);
            remove(old); remove(bad);                    /* 转正了就不用回滚: 旧版程序删掉(Windows 上还被占着就删不掉, 下次再说) */
        }
        else if (now - trial_ms > env_s("CUSTHUB_REL_TRIAL_S", 120)) rollback(from, to, "试用期内没连上网络");
    }
    if (J.fh >= 0) {
        int r = p_fetch_poll(J.fh);
        if (r != 0) { J.fh = -1; src_finished(r > 0); }
    } else if (J.active && J.sock < 0 && now - J.started > 600000) { logf_("取 %s 超时", J.asset); job_stop_src(); J.active = 0; }
    http_tick();
    if (!J.active && now >= next_check) {
        next_check = now + env_s("CUSTHUB_REL_CHECK_S", 30);   /* 每台 30 秒问一次发布清单(约 2KB); 网内看到更新的版本 3 秒内就去取(rel_saw) */
        check_now();
    }
}

/* ---------- pkg 服务(给别人取包): 请求 "pkg:<附件名>:<从第几字节>" ---------- */
#define MAXPS 8
static void slot_free(int k);
static struct { int used, s; FILE *f; char *mem; size_t mlen, mo; uint8_t b[16384]; size_t n, o; int64_t born; } PS[MAXPS];

int pkg_accept(const char *req, char *why, size_t wcap)
{
    char asset[100]; long off = 0;
    const char *a = req + 4, *c = strrchr(a, ':');
    if (!c || (size_t)(c - a) >= sizeof asset || c == a) { snprintf(why, wcap, "请求格式不对"); return -1; }
    memcpy(asset, a, (size_t)(c - a)); asset[c - a] = 0;
    off = atol(c + 1);
    for (const char *x = asset; *x; x++)
        if (!((*x >= 'a' && *x <= 'z') || (*x >= 'A' && *x <= 'Z') || (*x >= '0' && *x <= '9') || *x == '.' || *x == '-' || *x == '_')) { snprintf(why, wcap, "名字不对"); return -1; }
    if (strncmp(asset, "custhub3", 8) || strstr(asset, "..")) { snprintf(why, wcap, "名字不对"); return -1; }
    char p[400], n[120];
    if (!strcmp(asset, "custhub3.release")) snprintf(n, sizeof n, "rel.release"); else snprintf(n, sizeof n, "rel-%s", asset);
    path_in(p, sizeof p, n);
    for (int k = 0; k < MAXPS; k++) if (!PS[k].used) {
        FILE *f = fopen(p, "rb");
        if (!f) { snprintf(why, wcap, "本机没有这个包"); return -1; }
        if (off < 0 || fseek(f, off, SEEK_SET)) { fclose(f); snprintf(why, wcap, "位置不对"); return -1; }
        int fd[2];
        if (p_pair(fd)) { fclose(f); snprintf(why, wcap, "开不了通道"); return -1; }
        memset(&PS[k], 0, sizeof PS[k]);
        PS[k].used = 1; PS[k].s = fd[1]; PS[k].f = f; PS[k].born = now_ms();
        return fd[0];
    }
    snprintf(why, wcap, "取包的人太多");
    return -1;
}

void pkg_poll_add(pfd_t *p, int *np, int *map)
{
    for (int k = 0; k < MAXPS; k++) if (PS[k].used) { p[*np].fd = PS[k].s; p[*np].ev = P_OUT; map[(*np)++] = 5000 + k; }
}

void pkg_io(int k, short rev)
{
    if (k < 0 || k >= MAXPS || !PS[k].used) return;
    if (rev & P_HUP) goto done;
    if (!(rev & P_OUT)) return;
    if (PS[k].o == PS[k].n) {                            /* 先发头(HTTP), 再发内存里的内容, 再发文件 */
        PS[k].o = 0;
        if (PS[k].mem && PS[k].mo < PS[k].mlen) { size_t m = PS[k].mlen - PS[k].mo; if (m > sizeof PS[k].b) m = sizeof PS[k].b; memcpy(PS[k].b, PS[k].mem + PS[k].mo, m); PS[k].mo += m; PS[k].n = m; }
        else PS[k].n = PS[k].f ? fread(PS[k].b, 1, sizeof PS[k].b, PS[k].f) : 0;
        if (!PS[k].n) goto done;
    }
    long w = p_send(PS[k].s, PS[k].b + PS[k].o, PS[k].n - PS[k].o);
    if (w > 0) PS[k].o += (size_t)w; else if (w == P_FAIL) goto done;
    return;
done:
    slot_free(k);
}

static void slot_free(int k)
{
    if (PS[k].f) fclose(PS[k].f);
    free(PS[k].mem);
    p_shut_wr(PS[k].s); p_close(PS[k].s);
    memset(&PS[k], 0, sizeof PS[k]);
}

/* ---------- 只读 HTTP(给还没装 custhub 的机器: 接入命令里的地址换成任一台可达机器的 http://IP:端口) ----------
 * 监听口上第一个包以 "GET " 开头就交到这里(连通层的握手第一条不会这样开头); 路径照抄 GitHub Release:
 *   /releases/latest/download/custhub3.release | custhub3.seed(按本机当前名单现出) | custhub3-join.ps1 | custhub3-join.sh
 *   /releases/download/v<版本>/custhub3-<版本>-<平台>[.exe]    只给手上最新清单里的
 * 接入脚本发出去时把里面的 GitHub 地址换成请求里的 Host, 后面的下载都回到本机; 只读, 发完就关 */
void master_line(char *out, size_t cap);

static char *script_for(const char *plat, const char *host, size_t *len)
{
    char asset[96], n[120], p[400], from[160], to[160];
    asset_of(R.ver, plat, asset, sizeof asset);
    snprintf(n, sizeof n, "rel-%s", asset); path_in(p, sizeof p, n);
    static char t[65536];
    long k = m_read(p, t, sizeof t - 1);
    if (k <= 0 || !G.github[0]) return NULL;
    t[k] = 0;
    snprintf(from, sizeof from, "https://github.com/%s/releases", G.github);
    snprintf(to, sizeof to, "http://%s/releases", host);
    char *o = malloc((size_t)k * 2 + 1024); size_t ol = 0;
    if (!o) return NULL;
    for (const char *s = t; *s; ) {
        const char *h = strstr(s, from);
        size_t pre = h ? (size_t)(h - s) : strlen(s);
        if (ol + pre + strlen(to) + 1 > (size_t)k * 2 + 1024) { free(o); return NULL; }
        memcpy(o + ol, s, pre); ol += pre; s += pre;
        if (h) { memcpy(o + ol, to, strlen(to)); ol += strlen(to); s += strlen(from); }
    }
    *len = ol;
    return o;
}

static char *seed_now(size_t *len)
{
    if (!G.trust.tlen) return NULL;
    char ml[200]; master_line(ml, sizeof ml);
    static char hs[MAXM * 200]; hints_text(hs, sizeof hs);   /* 可达地址: 老版本的 join 只认 master / github, 多的行不看 */
    char *o = malloc(G.trust.tlen + 512 + strlen(hs));
    if (!o) return NULL;
    int n = snprintf(o, 512 + strlen(hs), "custhub-seed v1\nmaster %s\ngithub %s\n%s--trust--\n", ml, G.github[0] ? G.github : "-", hs);
    memcpy(o + n, G.trust.text, G.trust.tlen);
    *len = (size_t)n + G.trust.tlen;
    return o;
}

static int name_ok_http(const char *s)
{
    if (!*s || strncmp(s, "custhub3", 8) || strstr(s, "..")) return 0;
    for (; *s; s++) if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '.' || *s == '-' || *s == '_')) return 0;
    return 1;
}

static void http_reply(int fd, const char *status)
{
    char h[200]; int n = snprintf(h, sizeof h, "HTTP/1.0 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s\n", status, status);
    p_send(fd, h, (size_t)n); p_shut_wr(fd); p_close(fd);
}

void http_take(int fd, const char *req, size_t n, const char *peer)
{
    char line[400], path[300] = "", host[100] = "";
    size_t l = 0; while (l < n && l < sizeof line - 1 && req[l] != '\r' && req[l] != '\n') { line[l] = req[l]; l++; } line[l] = 0;
    if (sscanf(line, "GET %299s", path) != 1) { http_reply(fd, "400 Bad Request"); return; }
    char *q = strchr(path, '?'); if (q) *q = 0;
    for (const char *h = req; h && h < req + n; h = strchr(h, '\n')) {
        if (*h == '\n') h++;
        if (!strncmp(h, "Host:", 5) || !strncmp(h, "host:", 5)) { sscanf(h + 5, " %99[^\r\n ]", host); break; }
    }
    for (char *c = host; *c; c++) if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || *c == '.' || *c == ':' || *c == '-' || *c == '[' || *c == ']')) { host[0] = 0; break; }
    if (!strcmp(path, "/whoami") && peer) {             /* 打洞用的 STUN: 回对方在本机看来的地址:端口 */
        char h[200]; int hn = snprintf(h, sizeof h, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s\n", peer);
        p_send(fd, h, (size_t)hn); p_shut_wr(fd); p_close(fd); return;
    }
    if (!R.ver[0]) { http_reply(fd, "503 Service Unavailable"); return; }
    const char *lat = "/releases/latest/download/", *dl = "/releases/download/v";
    char file[400] = "", *mem = NULL; size_t mlen = 0;
    if (!strncmp(path, lat, strlen(lat))) {
        const char *nm = path + strlen(lat);
        if (!strcmp(nm, "custhub3.release")) path_in(file, sizeof file, "rel.release");
        else if (!strcmp(nm, "custhub3.seed")) mem = seed_now(&mlen);
        else if (!strcmp(nm, "custhub3-join.ps1") && host[0]) mem = script_for("join.ps1", host, &mlen);
        else if (!strcmp(nm, "custhub3-join.sh") && host[0]) mem = script_for("join.sh", host, &mlen);
    } else if (!strcmp(path, "/ps1") && host[0]) { mem = script_for("join.ps1", host, &mlen);    /* 短地址: 接入命令要塞进 Win+R(259 字) */
    } else if (!strcmp(path, "/sh") && host[0]) { mem = script_for("join.sh", host, &mlen);
    } else if (!strncmp(path, dl, strlen(dl))) {
        const char *v = path + strlen(dl), *sl = strchr(v, '/');
        char pre[64]; snprintf(pre, sizeof pre, "custhub3-%s-", R.ver);
        if (sl && (size_t)(sl - v) == strlen(R.ver) && !strncmp(v, R.ver, strlen(R.ver)) && name_ok_http(sl + 1) && !strncmp(sl + 1, pre, strlen(pre))) {
            char nn[300]; snprintf(nn, sizeof nn, "rel-%s", sl + 1); path_in(file, sizeof file, nn);
        }
    }
    FILE *f = NULL; long size = 0;
    if (!mem && file[0] && (f = fopen(file, "rb"))) { fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, 0, SEEK_SET); }
    if (!mem && !f) { http_reply(fd, "404 Not Found"); return; }
    if (mem) size = (long)mlen;
    for (int k = 0; k < MAXPS; k++) if (!PS[k].used) {
        memset(&PS[k], 0, sizeof PS[k]);
        PS[k].used = 1; PS[k].s = fd; PS[k].f = f; PS[k].mem = mem; PS[k].mlen = mlen; PS[k].born = now_ms();
        PS[k].n = (size_t)snprintf((char *)PS[k].b, sizeof PS[k].b, "HTTP/1.0 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n",
                                      mem ? "text/plain; charset=utf-8" : "application/octet-stream", size);   /* 脚本注明 UTF-8: Win7 的 WebClient 不注明就按 GBK 解, 中文会吞掉换行 */
        logf_("HTTP 发 %s 给 %s", path, host[0] ? host : "?");
        return;
    }
    if (f) fclose(f);
    free(mem);
    http_reply(fd, "503 Service Unavailable");
}

void http_tick(void)                                     /* 卡住的下载 10 分钟后收掉 */
{
    int64_t now = now_ms();
    for (int k = 0; k < MAXPS; k++) if (PS[k].used && now - PS[k].born > 600000) slot_free(k);
}
