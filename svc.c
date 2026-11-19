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
    if (pass_allows(&P, P.key, G.id.ed, req, wall_ms() / 1000, why, wcap)) goto deny;
    if (!strcmp(req, "sh")) { int fd = sh_accept(why, wcap); if (fd >= 0) return fd; goto deny; }
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

int pass_load(char *buf, size_t cap)
{
    char p[300];
    snprintf(p, sizeof p, "%s/pass", G.dir);
    long n = m_read(p, buf, cap);
    return n > 0 ? (int)n : 0;
}
