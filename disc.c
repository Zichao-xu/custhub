/* 找人: 成员名单(主钥匙 SSHSIG 签, 版本只升不降) + 位置记录(节点自签, 序号大者胜), 两者都在链路上互传
 * 名单格式:
 *   custhub-mesh-trust <版本>
 *   node  <名字> <公钥 base64>
 *   relay <名字> <公钥 base64> <地址:端口>
 *   --end--
 *   -----BEGIN SSH SIGNATURE----- …(ssh-keygen -Y sign -n custhub-mesh-trust)
 * 位置记录: rec <公钥> <序号> <relay|node> <对外地址|-> <挂着的可达节点,…|-> <各可达节点状态,…|-> <版本> <签名> */
#include "mesh.h"
#include "vendor/monocypher-ed25519.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sshsig_verify(const char *armored, const uint8_t *msg, size_t mlen, const char *ns, uint8_t (*keys)[32], int nkeys);

#define NS "custhub-mesh-trust"

const char *name_of(const uint8_t ed[32])
{
    static char ring[4][40]; static int k;
    member_t *m = member_by_ed(ed);
    char *o = ring[k++ & 3];
    if (m) snprintf(o, 40, "%s", m->name);
    else { char id[9]; short_id(ed, id); snprintf(o, 40, "?%s", id); }
    return o;
}

member_t *member_by_ed(const uint8_t ed[32])
{
    for (int i = 0; i < G.trust.n; i++) if (!memcmp(G.trust.m[i].ed, ed, 32)) return &G.trust.m[i];
    return NULL;
}
member_t *member_by_x(const uint8_t x[32])
{
    for (int i = 0; i < G.trust.n; i++) if (!memcmp(G.trust.m[i].x, x, 32)) return &G.trust.m[i];
    return NULL;
}
member_t *member_by_name(const char *name)
{
    for (int i = 0; i < G.trust.n; i++) if (!strcmp(G.trust.m[i].name, name)) return &G.trust.m[i];
    return NULL;
}
rec_t *rec_by_ed(const uint8_t ed[32])
{
    for (int i = 0; i < G.nr; i++) if (!memcmp(G.r[i].ed, ed, 32)) return &G.r[i];
    return NULL;
}

static int ok_name(const char *s)
{
    if (!*s || strlen(s) >= 32) return 0;
    for (; *s; s++) if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '-' || *s == '_')) return 0;
    return 1;
}

int mtrust_parse(const char *text, size_t len, trust_t *t, const uint8_t master[32])
{
    if (len >= MAXTEXT) return -1;
    char buf[MAXTEXT];
    memcpy(buf, text, len); buf[len] = 0;
    char *end = strstr(buf, "\n--end--\n");
    if (!end || strncmp(buf, NS " ", strlen(NS) + 1)) return -1;
    size_t dlen = (size_t)(end - buf) + 9;
    uint8_t mk[1][32]; memcpy(mk[0], master, 32);
    if (!sshsig_verify(buf + dlen, (const uint8_t *)buf, dlen, NS, mk, 1)) return -1;
    memset(t, 0, sizeof *t);
    buf[dlen] = 0;
    char *save = NULL;
    for (char *ln = m_tok(buf, "\n", &save); ln; ln = m_tok(NULL, "\n", &save)) {
        char a[24], nm[40], k[64], ad[64];
        int f = sscanf(ln, "%23s %39s %63s %63s", a, nm, k, ad);
        if (!strcmp(a, NS)) { t->ver = atol(nm); continue; }
        if (!strcmp(a, "--end--")) break;
        int relay = !strcmp(a, "relay");                   /* 老写法 relay; 新写法 node 后面跟地址 = 种子线索 */
        if ((!relay && strcmp(a, "node")) || f < 3 || (relay && f < 4) || !ok_name(nm) || t->n >= MAXM) return -1;
        if (!relay && f >= 4 && strncmp(ad, "host=", 5)) relay = 1;
        member_t *m = &t->m[t->n++];
        snprintf(m->name, sizeof m->name, "%s", nm);
        if (b64_decode(k, strlen(k), m->ed, 32) != 32) return -1;
        ed_to_x(m->ed, m->x);
        m->relay = relay;
        if (relay) snprintf(m->addr, sizeof m->addr, "%s", ad);
        const char *h = strstr(ln, " host=");               /* 备注: 老版本按空格只读前 4 段, 多出来的不认也不报错 */
        if (h) sscanf(h + 6, "%63s", m->host);
    }
    if (t->ver <= 0) return -1;
    memcpy(t->text, text, len); t->tlen = len;
    return 0;
}

static void recompute_role(void) { }                  /* 可达节点不再由名单决定(qual.c 自检) */

int ed_relay(const uint8_t ed[32])
{
    member_t *m = member_by_ed(ed);
    if (!m) return 0;
    rec_t *r = rec_by_ed(ed);
    return (r && r->relay) || (m->relay && m->addr[0]);
}

int mtrust_apply(const char *text, size_t len, const char *from)
{
    static trust_t nt;
    if (mtrust_parse(text, len, &nt, G.master)) { logf_("%s 给的名单验签不过, 丢弃", from); return -1; }
    if (nt.ver <= G.trust.ver) return 0;
    long old = G.trust.ver;
    int was_member = member_by_ed(G.id.ed) != NULL;
    G.trust = nt;
    char p[300]; snprintf(p, sizeof p, "%s/trust", G.dir);
    m_write(p, G.trust.text, G.trust.tlen);
    logf_("名单 v%ld → v%ld(来自 %s)", old, G.trust.ver, from);
    recompute_role();
    relay_sync();
    if (!was_member && member_by_ed(G.id.ed)) {         /* 刚被批准: 报到时的链路在可达节点那边还算报到, 断掉马上按成员重新接入 */
        member_t *me = member_by_ed(G.id.ed);
        if (me) snprintf(G.name, sizeof G.name, "%s", me->name);
        logf_("已被批准(名单 v%ld 里有本机, 名字 %s), 重新接入", G.trust.ver, G.name);
        for (int i = 0; i < MAXC; i++) if (G.c[i].state != C_FREE && G.c[i].initiator && !G.c[i].guest && !G.c[i].probe_for) conn_close(i, "被批准, 重新接入");
    }
    else if (member_by_ed(G.id.ed) && strcmp(G.name, member_by_ed(G.id.ed)->name)) {   /* 被改名了: 本机跟着改 */
        logf_("本机改名: %s → %s", G.name, member_by_ed(G.id.ed)->name);
        snprintf(G.name, sizeof G.name, "%s", member_by_ed(G.id.ed)->name);
    }
    for (int i = 0; i < MAXC; i++) {
        conn_t *c = &G.c[i];
        if (c->state == C_FREE || c->closing || (c->guest && !c->initiator)) continue;   /* 访客链路不靠名单 */
        c->pm = member_by_ed(c->peer);
        if (!c->pm) { conn_close(i, "已从名单移除"); continue; }
        c->peer_relay = ed_relay(c->peer);
    }
    for (int i = 0; i < G.nr; i++) if (!member_by_ed(G.r[i].ed)) { G.r[i] = G.r[--G.nr]; i--; }
    targets_sync();
    for (int t = 0; t < G.nt; t++) if (G.t[t].conn < 0) { G.t[t].next_try = 0; G.t[t].backoff = 1000; }   /* 新名单 = 新线索, 马上重试 */
    for (int i = 0; i < MAXC; i++) if (G.c[i].state == C_UP) conn_send(i, F_TRUST, 0, G.trust.text, G.trust.tlen);
    return 1;
}

void targets_sync(void)
{
    target_t old[MAXT]; int no = G.nt;
    memcpy(old, G.t, sizeof old);
    G.nt = 0;
    /* 候选 = 名单里带地址的成员(种子线索) + 位置记录里自己声明了可达节点的成员; 挂之前自己连一次, 握手就是确认 */
    for (int i = 0; i < G.trust.n && G.nt < MAXT; i++) {
        member_t *m = &G.trust.m[i];
        if (!ed_relay(m->ed) || !memcmp(m->ed, G.id.ed, 32)) continue;
        target_t *t = &G.t[G.nt++];
        int found = 0;
        for (int k = 0; k < no; k++) if (!memcmp(old[k].ed, m->ed, 32)) { *t = old[k]; found = 1; break; }
        if (!found) { memset(t, 0, sizeof *t); memcpy(t->ed, m->ed, 32); t->conn = -1; t->backoff = 1000; snprintf(t->why, sizeof t->why, "未连"); }
        snprintf(t->name, sizeof t->name, "%s", m->name);
        const char *addr = m->addr;
        rec_t *r = rec_by_ed(m->ed);
        if (r && r->relay && strcmp(r->addr, "-")) addr = r->addr;   /* 可达节点自报的地址先试 */
        /* 自报的可能过时(可达节点又搬了、记录还在), 名单的可能过时(还没改名单): 两个不同就轮流试 */
        snprintf(t->alt, sizeof t->alt, "%s", m->addr[0] && strcmp(addr, m->addr) ? m->addr : "");
        if (strcmp(t->addr, addr)) {
            if (found) logf_("%s 地址 %s → %s", m->name, t->addr, addr);
            snprintf(t->addr, sizeof t->addr, "%s", addr);
            if (t->conn < 0) { t->next_try = 0; t->backoff = 1000; }
        }
    }
    /* 正在拨的链路记的是旧下标, 重新对上 */
    for (int i = 0; i < MAXC; i++) if (G.c[i].state != C_FREE) G.c[i].target = -1;
    for (int t = 0; t < G.nt; t++) if (G.t[t].conn >= 0) {
        if (G.c[G.t[t].conn].state == C_FREE) G.t[t].conn = -1; else G.c[G.t[t].conn].target = t;
    }
}

/* 本机是什么机器: 平台|机器名|系统|机型, 只算一次; 空格换成 _、逗号换成 .(记录里按空格分段) */
const char *my_info(void)
{
    static char inf[120];                               /* 记录一整行最长 800, 留够余量 */
    if (inf[0]) return inf;
    char host[64], os[96], model[96], raw[400];
    p_hostname(host, sizeof host); p_machine(os, sizeof os, model, sizeof model);
    snprintf(raw, sizeof raw, "%s|%.40s|%.50s|%.50s", CH_PLAT, host, os, model);
    size_t o = 0;
    for (const char *c = raw; *c && o + 1 < sizeof inf; c++) {
        char ch = *c;
        if (ch == ' ' || ch == '\t') ch = '_';
        if (ch == ',') ch = '.';                          /* 逗号是记录里可达节点列表的分隔符(Mac15,6 → Mac15.6) */
        if (ch == '\r' || ch == '\n' || (unsigned char)ch < 32) continue;
        inf[o++] = ch;
    }
    inf[o] = 0;
    return inf;
}

/* ---------- 位置记录 ---------- */
static int rec_parse(const char *line, size_t n, rec_t *r)
{
    if (n >= sizeof r->line) return -1;
    char b[800]; memcpy(b, line, n); b[n] = 0;
    char *sp = strrchr(b, ' ');
    if (!sp) return -1;
    uint8_t sig[64];
    if (b64_decode(sp + 1, strlen(sp + 1), sig, 64) != 64) return -1;
    char f[8][320]; int k = 0;
    char tmp[800]; memcpy(tmp, b, (size_t)(sp - b)); tmp[sp - b] = 0;
    char *save = NULL;
    for (char *t = m_tok(tmp, " ", &save); t && k < 8; t = m_tok(NULL, " ", &save)) snprintf(f[k++], 320, "%s", t);
    if (k != 8 || strcmp(f[0], "rec")) return -1;
    memset(r, 0, sizeof *r);
    if (b64_decode(f[1], strlen(f[1]), r->ed, 32) != 32) return -1;
    if (crypto_ed25519_check(sig, r->ed, (const uint8_t *)b, (size_t)(sp - b))) return -1;
    r->seq = strtoull(f[2], NULL, 10);
    r->relay = !strcmp(f[3], "relay");
    snprintf(r->addr, sizeof r->addr, "%s", f[4]);
    snprintf(r->relays, sizeof r->relays, "%s", f[5]);
    snprintf(r->status, sizeof r->status, "%s", f[6]);
    char *bar = strchr(f[7], '|');                       /* 版本|平台|机器名|系统|机型: 老版本只认前面的版本号 */
    if (bar) { *bar = 0; snprintf(r->info, sizeof r->info, "%s", bar + 1); }
    snprintf(r->ver, sizeof r->ver, "%s", f[7]);
    memcpy(r->line, line, n); r->line[n] = 0;
    return 0;
}

static void flood(int except, const char *line)
{
    for (int i = 0; i < MAXC; i++) if (i != except && G.c[i].state == C_UP) conn_send(i, F_REC, 0, line, strlen(line));
}

void disc_rec_in(int from, const char *line, size_t n)
{
    rec_t r;
    if (rec_parse(line, n, &r)) return;
    member_t *m = member_by_ed(r.ed);
    if (!m || !memcmp(r.ed, G.id.ed, 32)) return;
    rec_t *cur = rec_by_ed(r.ed);
    if (cur && r.seq <= cur->seq) return;
    int fresh = !cur;
    if (!cur) { if (G.nr >= MAXR) return; cur = &G.r[G.nr++]; }
    int changed = fresh ? r.relay : (r.relay != cur->relay || (r.relay && strcmp(cur->addr, r.addr)));   /* 可达节点声明有变 */
    r.rx_ms = now_ms();
    *cur = r;
    rel_saw(r.ver);
    if (changed) {
        targets_sync();
        for (int i = 0; i < MAXC; i++) if (G.c[i].state == C_UP && !memcmp(G.c[i].peer, r.ed, 32)) G.c[i].peer_relay = ed_relay(r.ed);
    }
    flood(from, cur->line);
}

void disc_on_up(int i)
{
    conn_send(i, F_TRUST, 0, G.trust.text, G.trust.tlen);
    for (int k = 0; k < G.nr; k++) conn_send(i, F_REC, 0, G.r[k].line, strlen(G.r[k].line));
    G.mypub_ms = 0;                                    /* 下一轮立刻重发自己的记录 */
}

static void clean(char *s) { for (; *s; s++) if (*s == ' ' || *s == ',' || *s == ':') *s = '_'; }

void disc_tick(void)
{
    int64_t now = now_ms();
    char relays[160] = "", status[320] = "", body[700], b64[48];
    int any_up = 0;
    for (int t = 0; t < G.nt; t++) {
        int up = conn_by_peer(G.t[t].ed) >= 0;
        if (up) { any_up = 1; if (relays[0]) strcat(relays, ","); strncat(relays, G.t[t].name, sizeof relays - strlen(relays) - 1); }
        char why[100]; snprintf(why, sizeof why, "%s", up ? "up" : G.t[t].why); clean(why);
        char item[140]; snprintf(item, sizeof item, "%s%s:%s", status[0] ? "," : "", G.t[t].name, why);
        strncat(status, item, sizeof status - strlen(status) - 1);
    }
    if (any_up) G.last_up_ms = now;
    b64_encode(G.id.ed, 32, b64);
    snprintf(body, sizeof body, "%s %s %s %s %s|%s", G.me_relay ? "relay" : "node",
             G.me_relay ? relay_addr() : "-", relays[0] ? relays : "-", status[0] ? status : "-", CH_VERSION, my_info());
    if (strcmp(body, G.mybody) || now - G.mypub_ms > 20000) {
        uint64_t wall = (uint64_t)wall_ms();
        G.myseq = wall > G.myseq ? wall : G.myseq + 1;
        char full[800], sigb[100]; uint8_t sig[64];
        int n = snprintf(full, sizeof full, "rec %s %llu %s", b64, (unsigned long long)G.myseq, body);
        crypto_ed25519_sign(sig, G.id.edsk, (const uint8_t *)full, (size_t)n);
        b64_encode(sig, 64, sigb);
        snprintf(full + n, sizeof full - (size_t)n, " %s", sigb);
        snprintf(G.mybody, sizeof G.mybody, "%s", body);
        G.mypub_ms = now;
        flood(-1, full);
    }
    /* 兜底: 节点一台可达节点都挂不上超过 10 秒 → 读兜底来源的名单; 可达节点每 10 秒看一次(管理员放新名单的地方)
     * 来源是本地文件: 客户机守护从中转 HTTP 取来放这里, 中转上是管理员 put 的那份; 以后加 GitHub Release */
    if (G.fallback[0] && now - G.last_fb_ms > 10000 && (G.me_relay || (!any_up && now - G.last_up_ms > 10000))) {
        G.last_fb_ms = now;
        static char t[MAXTEXT];
        long n = m_read(G.fallback, t, sizeof t);
        if (n > 0) {
            int r = mtrust_apply(t, (size_t)n, "兜底来源");
            if (r != 0 || !G.me_relay) logf_("查兜底来源: %s", r > 0 ? "拿到新名单" : r == 0 ? "没有更新的" : "验签不过");
        }
    }
}

/* ---------- 待批准查询: 只回答主钥匙当场签过的请求(5 分钟内), 名单外机器的名字和来源地址不外泄给其他成员 ---------- */
#define PNS "custhub-mesh-pending"
void disc_pendq(int from, const uint8_t *pl, size_t n)
{
    if ((!G.me_relay && !me_seed()) || n > 4000) return;   /* 收报到的(可达节点, 或还没自检通过的种子)才有待批准 */
    char t[4096]; memcpy(t, pl, n); t[n] = 0;
    char *nl = strchr(t, '\n');
    long long ts;
    if (!nl || sscanf(t, PNS " %lld", &ts) != 1) return;
    long long now = wall_ms() / 1000;
    uint8_t mk[1][32]; memcpy(mk[0], G.master, 32);
    if (ts < now - 300 || ts > now + 300 || !sshsig_verify(nl + 1, (const uint8_t *)t, (size_t)(nl - t + 1), PNS, mk, 1)) {
        logf_("%s 的待批准查询没有有效的主钥匙签名, 不答", name_of(G.c[from].peer)); return;
    }
    static char p[300], body[60000];
    snprintf(p, sizeof p, "%s/pending", G.dir);
    long bn = m_read(p, body, sizeof body);
    conn_send(from, F_PENDA, 0, body, bn > 0 ? (size_t)bn : 0);
}

void disc_penda(int from, const uint8_t *pl, size_t n)
{
    if (G.pq_fd <= 0 || !G.c[from].peer_relay) return;
    char t[60001]; size_t k = n < 60000 ? n : 60000; memcpy(t, pl, k); t[k] = 0;
    char *sv = NULL;
    for (char *l = m_tok(t, "\n", &sv); l; l = m_tok(NULL, "\n", &sv)) {
        char o[700]; int on = snprintf(o, sizeof o, "%s %s\n", name_of(G.c[from].peer), l);
        buf_add(&G.pq_out, o, (size_t)on);
    }
    G.pq_wait--;
}

void disc_pend_tick(void)
{
    if (G.pq_fd <= 0 || (G.pq_wait > 0 && now_ms() < G.pq_deadline)) return;
    p_block(G.pq_fd);
    if (G.pq_wait > 0) { const char *w = "# 有节点没回答(超时)\n"; p_send(G.pq_fd, w, strlen(w)); }
    if (G.pq_out.len) p_send(G.pq_fd, G.pq_out.p, G.pq_out.len);
    p_close(G.pq_fd); G.pq_fd = 0; buf_free(&G.pq_out);
}

int mesh_conf_load(const char *dir)
{
    if (strlen(dir) >= sizeof G.dir - 40) { fprintf(stderr, "节点目录太长(最多 %d 个字节): %s\n", (int)sizeof G.dir - 40, dir); return -1; }
    snprintf(G.dir, sizeof G.dir, "%s", dir);
    char p[300], t[4096];
    snprintf(p, sizeof p, "%s/node.key", dir);
    if (ident_load(p, &G.id)) { fprintf(stderr, "读不了 %s(先 mesh keygen)\n", p); return -1; }
    snprintf(p, sizeof p, "%s/conf", dir);
    if (m_read(p, t, sizeof t) < 0) { fprintf(stderr, "读不了 %s\n", p); return -1; }
    int have_master = 0;
    char *save = NULL;
    for (char *ln = m_tok(t, "\n", &save); ln; ln = m_tok(NULL, "\n", &save)) {
        char k[16], v[300];
        if (sscanf(ln, "%15s %299[^\n]", k, v) != 2) continue;
        if (!strcmp(k, "name")) snprintf(G.name, sizeof G.name, "%s", v);
        else if (!strcmp(k, "listen")) snprintf(G.listen, sizeof G.listen, "%s", v);
        else if (!strcmp(k, "announce")) snprintf(G.announce, sizeof G.announce, "%s", v);
        else if (!strcmp(k, "ctl")) snprintf(G.ctl, sizeof G.ctl, "%s", v);
        else if (!strcmp(k, "fallback")) snprintf(G.fallback, sizeof G.fallback, "%s", v);
        else if (!strcmp(k, "dump")) G.dump = atoi(v);
        else if (!strcmp(k, "relay")) G.relay_off = !strcmp(v, "off");
        else if (!strcmp(k, "upnp")) G.upnp_off = !strcmp(v, "off");
        else if (!strcmp(k, "github")) snprintf(G.github, sizeof G.github, "%s", v);
        else if (!strcmp(k, "release_base")) snprintf(G.relbase, sizeof G.relbase, "%s", v);
        else if (!strcmp(k, "hello")) snprintf(G.hello, sizeof G.hello, "%s", v);
        else if (!strcmp(k, "log")) log_open(v);
        else if (!strcmp(k, "master")) have_master = !ssh_pub(v, G.master);
        else if (!strcmp(k, "allow")) {
            char *s2 = NULL;
            for (char *x = m_tok(v, " ", &s2); x && G.nallow < 16; x = m_tok(NULL, " ", &s2)) G.allow[G.nallow++] = atoi(x);
        }
    }
    if (!have_master) { logf_("conf 里缺 master(主公钥)"); return -1; }
    static char tt[MAXTEXT];
    snprintf(p, sizeof p, "%s/trust", dir);
    long n = m_read(p, tt, sizeof tt);
    if (n <= 0 || mtrust_parse(tt, (size_t)n, &G.trust, G.master)) { logf_("%s 缺失、格式不对或验签不过", p); return -1; }
    member_t *me = member_by_ed(G.id.ed);
    if (me && !G.name[0]) snprintf(G.name, sizeof G.name, "%s", me->name);
    recompute_role();
    G.last_up_ms = now_ms();
    logf_("启动: 名单 v%ld, %s%s", G.trust.ver, G.me_relay ? "可达(从外面连得进来)" : "节点", me ? "" : "(本机不在名单里, 只能等批准)");
    return 0;
}
