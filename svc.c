/* 服务层(design-v3 §0 第 4、11 条): 接收端把"谁、要开什么、带的通行证"交到这里
 *   先问通行证模块(默认拒绝: 没有通行证一律不开, 名单成员也一样), 再接到本机服务
 *   服务平级注册, 互不认识: 本机端口(请求 "port:<n>", 还要在 conf 的 allow 里)、shell(请求 "sh", sh.c); 以后 cp 也加在这里 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int svc_port(int p, char *why, size_t wcap)
{
    int ok = 0;
    for (int k = 0; k < G.nallow; k++) if (G.allow[k] == p) ok = 1;
    if (!ok) { snprintf(why, wcap, "端口不开放"); return -1; }
    char w[64];
    int fd = p_dial("127.0.0.1", p, 0, w, sizeof w);
    if (fd < 0) { snprintf(why, wcap, "本机这个端口没有服务"); return -1; }
    p_nb(fd);
    return fd;
}

int svc_open(const uint8_t rs[32], const char *req, const char *pass, size_t plen, uint8_t who[32], char *why, size_t wcap)
{
    static pass_t P;
    char id[9]; uint8_t x[32];
    memset(who, 0, 32);
    if (!strncmp(req, "pkg:", 4)) {                    /* 取包: 包本来就是公开的, 免通行证, 只对名单成员开(design-v3 §0 第 15 条) */
        member_t *m = member_by_x(rs);
        if (!m) { snprintf(why, wcap, "不是成员"); goto deny; }
        memcpy(who, m->ed, 32);
        int fd = pkg_accept(req, why, wcap);
        if (fd >= 0) return fd;
        goto deny;
    }
    if (!plen) { snprintf(why, wcap, "没有通行证"); goto deny; }
    if (pass_parse(pass, plen, G.master, &P, why, wcap)) goto deny;
    ed_to_x(P.key, x);
    if (memcmp(x, rs, 32)) { snprintf(why, wcap, "通行证不是发给这台机器的"); goto deny; }
    memcpy(who, P.key, 32);
    int okp = !pass_allows(&P, P.key, G.id.ed, !strncmp(req, "bench:", 6) ? "sh" : !strncmp(req, "info:", 5) ? "info" : req, wall_ms() / 1000, why, wcap);   /* 测速和 shell 同权限 */
    if (!okp && !strncmp(req, "info:", 5)) okp = !pass_allows(&P, P.key, G.id.ed, "sh", wall_ms() / 1000, why, wcap);   /* 只读查看: 通行证里有 info 或 sh 都行 */
    if (!okp && !strcmp(req, "file")) okp = !pass_allows(&P, P.key, G.id.ed, "sh", wall_ms() / 1000, why, wcap);    /* 传文件: 通行证里有 file 或 sh 都行 */
    if (!okp) goto deny;
    if (!strcmp(req, "sh")) { int fd = sh_accept(why, wcap); if (fd >= 0) return fd; goto deny; }
    if (!strncmp(req, "bench:", 6)) { int fd = bench_accept(req, why, wcap); if (fd >= 0) return fd; goto deny; }
    if (!strcmp(req, "file")) { int fd = file_accept(why, wcap); if (fd >= 0) return fd; goto deny; }
    if (!strncmp(req, "info:", 5)) { int fd = info_accept(req, why, wcap); if (fd >= 0) return fd; goto deny; }
    if (!strncmp(req, "port:", 5)) {
        char *e; long p = strtol(req + 5, &e, 10);
        if (e != req + 5 && !*e && p > 0 && p <= 65535) {
            int fd = svc_port((int)p, why, wcap);
            if (fd >= 0) return fd;
            goto deny;
        }
    }
    snprintf(why, wcap, "不认识的服务");
deny:
    short_id(who, id);
    logf_("拒绝 %s 开 %s: %s", member_by_ed(who) ? name_of(who) : id, req, why);
    return -1;
}

static void pass_slot(int k, char *p, size_t cap)
{
    if (k) snprintf(p, cap, "%s/pass.%d", G.dir, k); else snprintf(p, cap, "%s/pass", G.dir);
}

int pass_load(const uint8_t *dst, const char *svc, char *buf, size_t cap)
{
    static char t[PASSMAX + 1]; static pass_t P;
    char p[1300], why[120]; int fk = -1;
    int64_t now = wall_ms() / 1000;
    for (int k = 0; k < PASSSLOTS; k++) {
        pass_slot(k, p, sizeof p);
        long n = m_read(p, t, sizeof t);
        if (n <= 0 || (size_t)n > cap) continue;
        if (pass_parse(t, (size_t)n, G.master, &P, why, sizeof why)) { if (fk < 0) fk = k; continue; }   /* 验不过的也可能是唯一一张: 交给对方说原因 */
        if (!pass_allows(&P, G.id.ed, dst, svc && !strncmp(svc, "bench:", 6) ? "sh" : svc, now, why, sizeof why) ||
            (svc && !strcmp(svc, "file") && !pass_allows(&P, G.id.ed, dst, "sh", now, why, sizeof why)) ||
            (svc && !strncmp(svc, "info:", 5) && (!pass_allows(&P, G.id.ed, dst, "info", now, why, sizeof why) || !pass_allows(&P, G.id.ed, dst, "sh", now, why, sizeof why)))) { memcpy(buf, t, (size_t)n); return (int)n; }
        if (fk < 0) fk = k;
    }
    if (fk < 0) return 0;                       /* 没有合适的: 给第一张(对方会说拒绝原因; 取包不要通行证) */
    pass_slot(fk, p, sizeof p);
    long n = m_read(p, buf, cap);
    return n > 0 ? (int)n : 0;
}

static int same_scope(const pass_t *a, const pass_t *b)
{
    if (memcmp(a->key, b->key, 32) || a->to_all != b->to_all || a->nto != b->nto || strcmp(a->svc, b->svc)) return 0;
    for (int i = 0; i < a->nto; i++) if (memcmp(a->to[i], b->to[i], 32)) return 0;
    return 1;
}

int pass_store(const char *text, size_t len, char *slot, size_t scap)
{
    static pass_t N, P; static char t[PASSMAX + 1];
    char p[1300], why[120];
    if (pass_parse(text, len, G.master, &N, why, sizeof why)) { snprintf(slot, scap, "%s", why); return -1; }
    if (memcmp(N.key, G.id.ed, 32)) { snprintf(slot, scap, "不是发给本机的(通行证里的公钥不是本机节点的)"); return -1; }
    int64_t now = wall_ms() / 1000;
    int pick = -1, empty = -1, dead = -1, soon = -1; int64_t su = 0;
    for (int k = 0; k < PASSSLOTS; k++) {
        pass_slot(k, p, sizeof p);
        long n = m_read(p, t, sizeof t);
        if (n <= 0 || pass_parse(t, (size_t)n, G.master, &P, why, sizeof why)) { if (empty < 0) empty = k; continue; }
        if (same_scope(&N, &P)) { pick = k; break; }
        if (P.until <= now) { if (dead < 0) dead = k; continue; }
        if (soon < 0 || P.until < su) { soon = k; su = P.until; }
    }
    if (pick < 0) pick = empty >= 0 ? empty : dead >= 0 ? dead : soon;
    pass_slot(pick, p, sizeof p);
    if (m_write(p, text, len)) { snprintf(slot, scap, "写不了 %s", p); return -1; }
    snprintf(slot, scap, "%s", p);
    return 0;
}
