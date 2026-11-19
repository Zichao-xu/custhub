/* 通行证模块(design-v3 §0 第 11 条): 纯判断, 不碰网络、不碰系统、不读全局状态
 *   输入: 通行证原文、主公钥、谁在用、要进哪台、要用什么服务、现在几点 → 能 / 不能 + 原因
 *   和身份层并排、在连通层下面: 连通层问"能不能进网 / 帮不帮转", 服务层问"能不能用这个服务"
 *
 * 格式(和成员名单一样: 正文以 --end-- 结束, 后面接 ssh-keygen -Y sign -n custhub-pass 的签名):
 *   custhub-pass v1
 *   key   <发起方节点公钥 base64>
 *   to    all | <节点公钥 base64> ...
 *   svc   sh port:* port:22,3389        (任意组合, 空格分开)
 *   from  2026-11-19T18:00:00Z           (UTC)
 *   until 2026-11-19T20:00:00Z           (until - from 不超过 1 天)
 *   --end--
 *   -----BEGIN SSH SIGNATURE----- …(主钥匙) */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PNS "custhub-pass"

int sshsig_verify(const char *armored, const uint8_t *msg, size_t mlen, const char *ns, uint8_t (*keys)[32], int nkeys);

/* "YYYY-MM-DDTHH:MM:SSZ" → 1970 起的秒; 不对返回 -1 */
static int64_t utc_parse(const char *s)
{
    int y, mo, d, h, mi, se; char z;
    if (strlen(s) != 20 || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%c", &y, &mo, &d, &h, &mi, &se, &z) != 7 || z != 'Z') return -1;
    if (y < 2000 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 59 || h < 0 || mi < 0 || se < 0) return -1;
    y -= mo <= 2;                                      /* 公历日数(Howard Hinnant days_from_civil) */
    int64_t era = y / 400, yoe = y - era * 400;
    int64_t doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = era * 146097 + doe - 719468;
    return days * 86400 + h * 3600 + mi * 60 + se;
}

static int why_(char *why, size_t wcap, const char *m) { if (why) snprintf(why, wcap, "%s", m); return -1; }

int pass_parse(const char *text, size_t len, const uint8_t master[32], pass_t *p, char *why, size_t wcap)
{
    static char buf[PASSMAX + 1];
    if (len > PASSMAX) return why_(why, wcap, "通行证太长");
    memcpy(buf, text, len); buf[len] = 0;
    if (strncmp(buf, PNS " v1\n", strlen(PNS) + 4)) return why_(why, wcap, "不是通行证");
    char *end = strstr(buf, "\n--end--\n");
    if (!end) return why_(why, wcap, "通行证不完整");
    size_t dlen = (size_t)(end - buf) + 9;
    uint8_t mk[1][32]; memcpy(mk[0], master, 32);
    if (!sshsig_verify(buf + dlen, (const uint8_t *)buf, dlen, PNS, mk, 1)) return why_(why, wcap, "通行证签名不对");
    memset(p, 0, sizeof *p);
    p->from = p->until = -1;
    buf[dlen] = 0;
    int haskey = 0;
    char *save = NULL;
    for (char *ln = m_tok(buf, "\n", &save); ln; ln = m_tok(NULL, "\n", &save)) {
        char *sp = NULL, *k = m_tok(ln, " ", &sp), *v = sp ? sp : (char *)"";
        if (!k || !strcmp(k, PNS)) continue;
        if (!strcmp(k, "--end--")) break;
        if (!strcmp(k, "key")) { if (b64_decode(v, strlen(v), p->key, 32) != 32) return why_(why, wcap, "通行证 key 不对"); haskey = 1; }
        else if (!strcmp(k, "to")) {
            char *s2 = NULL;
            for (char *t = m_tok(v, " ", &s2); t; t = m_tok(NULL, " ", &s2)) {
                if (!strcmp(t, "all")) { p->to_all = 1; continue; }
                if (p->nto >= PASSTO || b64_decode(t, strlen(t), p->to[p->nto], 32) != 32) return why_(why, wcap, "通行证 to 不对");
                p->nto++;
            }
        }
        else if (!strcmp(k, "svc")) { if (strlen(v) >= sizeof p->svc) return why_(why, wcap, "通行证 svc 太长"); snprintf(p->svc, sizeof p->svc, "%s", v); }
        else if (!strcmp(k, "from")) p->from = utc_parse(v);
        else if (!strcmp(k, "until")) p->until = utc_parse(v);
        else if (!strcmp(k, "via")) return why_(why, wcap, "还不支持委派");
        else return why_(why, wcap, "通行证里有不认识的行");
    }
    if (!haskey) return why_(why, wcap, "通行证没有 key");
    if (!p->to_all && !p->nto) return why_(why, wcap, "通行证没有 to");
    if (!p->svc[0]) return why_(why, wcap, "通行证没有 svc");
    if (p->from < 0 || p->until < 0 || p->until <= p->from) return why_(why, wcap, "通行证有效期不对");
    if (p->until - p->from > PASSLIFE) return why_(why, wcap, "通行证有效期超过 1 天");
    return 0;
}

/* svc 行里有没有给这项服务: 请求是 "sh" 或 "port:<n>" */
static int svc_ok(const char *line, const char *req)
{
    char b[sizeof ((pass_t *)0)->svc];
    snprintf(b, sizeof b, "%s", line);
    int want_port = !strncmp(req, "port:", 5) ? atoi(req + 5) : -1;
    char *s = NULL;
    for (char *t = m_tok(b, " ", &s); t; t = m_tok(NULL, " ", &s)) {
        if (!strcmp(t, req)) return 1;
        if (want_port > 0 && !strncmp(t, "port:", 5)) {
            if (!strcmp(t + 5, "*")) return 1;
            char *s2 = NULL;
            for (char *n = m_tok(t + 5, ",", &s2); n; n = m_tok(NULL, ",", &s2)) if (atoi(n) == want_port) return 1;
        }
    }
    return 0;
}

int pass_allows(const pass_t *p, const uint8_t who[32], const uint8_t node[32], const char *svc, int64_t now_s, char *why, size_t wcap)
{
    if (memcmp(p->key, who, 32)) return why_(why, wcap, "通行证不是发给这台机器的");
    if (now_s + PASSSKEW < p->from) return why_(why, wcap, "通行证还没生效");
    if (now_s - PASSSKEW >= p->until) return why_(why, wcap, "通行证已过期");
    if (node && !p->to_all) {
        int in = 0;
        for (int i = 0; i < p->nto && !in; i++) in = !memcmp(p->to[i], node, 32);
        if (!in) return why_(why, wcap, "通行证不含这台机器");
    }
    if (svc && !svc_ok(p->svc, svc)) return why_(why, wcap, "通行证不含这项服务");
    return 0;
}
