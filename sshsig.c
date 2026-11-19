/* 身份层: ssh-keygen -Y sign 签名格式(OpenSSH PROTOCOL.sshsig) 的校验; 只认 ed25519 + sha512, 只认给定的公钥
 * (0.2 里"中转 CA 签发的 2 小时证书也能签"那条路随 6 位数验证码一起砍掉了, design-v3 §0 第 10 条)
 * 算法全部来自 Monocypher(含 ed25519 / sha512 模块, 与 OpenSSH 的 ed25519 兼容) */
#include "mesh.h"
#include "vendor/monocypher.h"
#include "vendor/monocypher-ed25519.h"
#include <string.h>

typedef struct { const uint8_t *p; size_t n; } rd_t;

static int rd_u32(rd_t *r, uint32_t *v)
{
    if (r->n < 4) return -1;
    *v = ((uint32_t)r->p[0] << 24) | ((uint32_t)r->p[1] << 16) | ((uint32_t)r->p[2] << 8) | r->p[3];
    r->p += 4; r->n -= 4;
    return 0;
}

static int rd_str(rd_t *r, const uint8_t **s, size_t *len)
{
    uint32_t l;
    if (rd_u32(r, &l) || l > r->n) return -1;
    *s = r->p; *len = l;
    r->p += l; r->n -= l;
    return 0;
}

static int is(const uint8_t *s, size_t n, const char *lit) { return n == strlen(lit) && memcmp(s, lit, n) == 0; }

static void put_str(uint8_t *b, size_t *o, const void *s, size_t n)
{
    b[(*o)++] = (uint8_t)(n >> 24); b[(*o)++] = (uint8_t)(n >> 16);
    b[(*o)++] = (uint8_t)(n >> 8);  b[(*o)++] = (uint8_t)n;
    memcpy(b + *o, s, n); *o += n;
}

#define BEGIN "-----BEGIN SSH SIGNATURE-----"
#define END   "-----END SSH SIGNATURE-----"

/* arm 是签名原文(可以带在别的文字后面); 签名钥匙是 keys 里的某一把、命名空间是 ns、签的是 msg → 1, 否则 0 */
int sshsig_verify(const char *arm, const uint8_t *msg, size_t mlen, const char *ns, uint8_t (*keys)[32], int nkeys)
{
    const char *b = strstr(arm, BEGIN), *e = strstr(arm, END);
    if (!b || !e || e < b) return 0;
    b += strlen(BEGIN);
    uint8_t blob[2048];
    long bl = b64_decode(b, (size_t)(e - b), blob, sizeof blob);
    if (bl < 10 || memcmp(blob, "SSHSIG", 6) != 0) return 0;
    rd_t r = { blob + 6, (size_t)bl - 6 };
    uint32_t ver;
    const uint8_t *pk, *sns, *res, *halg, *sig;
    size_t pkl, snsl, resl, halgl, sigl;
    if (rd_u32(&r, &ver) || ver != 1) return 0;
    if (rd_str(&r, &pk, &pkl) || rd_str(&r, &sns, &snsl) || rd_str(&r, &res, &resl) ||
        rd_str(&r, &halg, &halgl) || rd_str(&r, &sig, &sigl) || r.n != 0) return 0;
    if (!is(sns, snsl, ns) || !is(halg, halgl, "sha512") || resl > 256 || snsl > 64) return 0;
    rd_t k = { pk, pkl };                                  /* 公钥: string "ssh-ed25519" + string(32) */
    const uint8_t *kt, *kd; size_t ktl, kdl;
    if (rd_str(&k, &kt, &ktl) || rd_str(&k, &kd, &kdl) || k.n || !is(kt, ktl, "ssh-ed25519") || kdl != 32) return 0;
    rd_t s = { sig, sigl };                                /* 签名: string "ssh-ed25519" + string(64) */
    const uint8_t *st, *sd; size_t stl, sdl;
    if (rd_str(&s, &st, &stl) || rd_str(&s, &sd, &sdl) || s.n || !is(st, stl, "ssh-ed25519") || sdl != 64) return 0;
    int known = 0;
    for (int i = 0; i < nkeys && !known; i++) known = memcmp(keys[i], kd, 32) == 0;
    if (!known) return 0;
    /* 被签的内容: "SSHSIG" || string(命名空间) || string(保留) || string("sha512") || string(SHA512(消息)) */
    uint8_t h[64], tbs[6 + 4 + 64 + 4 + 256 + 4 + 6 + 4 + 64];
    size_t o = 6;
    crypto_sha512(h, msg, mlen);
    memcpy(tbs, "SSHSIG", 6);
    put_str(tbs, &o, sns, snsl); put_str(tbs, &o, res, resl); put_str(tbs, &o, "sha512", 6); put_str(tbs, &o, h, 64);
    return crypto_ed25519_check(sd, kd, tbs, o) == 0;
}
