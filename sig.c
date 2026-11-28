/* 身份层: 拼 SSHSIG 签名(OpenSSH PROTOCOL.sshsig), 与 ssh-keygen -Y sign 的输出逐字节同格式; 纯计算
 *   签名本身由持主钥匙的一方做(平台模块问 ssh-agent 要, 私钥不进本程序), 这里只管"要签什么"和"签完怎么包" */
#include "mesh.h"
#include "vendor/monocypher-ed25519.h"
#include <string.h>

static void put_u32(uint8_t *b, size_t *o, uint32_t v)
{
    b[(*o)++] = (uint8_t)(v >> 24); b[(*o)++] = (uint8_t)(v >> 16); b[(*o)++] = (uint8_t)(v >> 8); b[(*o)++] = (uint8_t)v;
}

static void put_str(uint8_t *b, size_t *o, const void *s, size_t n)
{
    put_u32(b, o, (uint32_t)n); memcpy(b + *o, s, n); *o += n;
}

size_t ssh_keyblob(const uint8_t pub[32], uint8_t out[51])
{
    size_t o = 0;
    put_str(out, &o, "ssh-ed25519", 11); put_str(out, &o, pub, 32);
    return o;
}

size_t sshsig_tbs(const char *ns, const uint8_t *msg, size_t mlen, uint8_t *out, size_t cap)
{
    uint8_t h[64];
    size_t nl = strlen(ns), o = 0;
    if (cap < 6 + 4 + nl + 4 + 4 + 6 + 4 + 64) return 0;
    crypto_sha512(h, msg, mlen);
    memcpy(out, "SSHSIG", 6); o = 6;
    put_str(out, &o, ns, nl);
    put_str(out, &o, "", 0);
    put_str(out, &o, "sha512", 6);
    put_str(out, &o, h, 64);
    return o;
}

size_t sshsig_armor(const uint8_t pub[32], const char *ns, const uint8_t sig[64], char *out, size_t cap)
{
    static uint8_t blob[512]; uint8_t kb[51], sb[96];
    size_t o = 0, so = 0, nl = strlen(ns);
    if (nl > 64) return 0;
    put_str(sb, &so, "ssh-ed25519", 11); put_str(sb, &so, sig, 64);
    memcpy(blob, "SSHSIG", 6); o = 6;
    put_u32(blob, &o, 1);
    put_str(blob, &o, kb, ssh_keyblob(pub, kb));
    put_str(blob, &o, ns, nl);
    put_str(blob, &o, "", 0);
    put_str(blob, &o, "sha512", 6);
    put_str(blob, &o, sb, so);
    static char b64[700];
    b64_encode(blob, o, b64);
    size_t bl = strlen(b64), w = 0;
    const char *B = "-----BEGIN SSH SIGNATURE-----\n", *E = "-----END SSH SIGNATURE-----\n";
    if (cap < strlen(B) + bl + bl / 70 + 2 + strlen(E) + 1) return 0;
    memcpy(out, B, strlen(B)); w = strlen(B);
    for (size_t i = 0; i < bl; i += 70) {                  /* ssh-keygen 每行 70 个字符 */
        size_t k = bl - i < 70 ? bl - i : 70;
        memcpy(out + w, b64 + i, k); w += k; out[w++] = '\n';
    }
    memcpy(out + w, E, strlen(E)); w += strlen(E);
    out[w] = 0;
    return w;
}

/* ssh-agent 协议(draft-miller-ssh-agent): 签名请求 / 回答; 收发由平台模块 p_agent_call 负责 */
size_t agent_sign_req(const uint8_t pub[32], const uint8_t *data, size_t n, uint8_t *out, size_t cap)
{
    uint8_t kb[51];
    size_t o = 4, kl = ssh_keyblob(pub, kb);
    if (cap < 4 + 1 + 4 + kl + 4 + n + 4) return 0;
    out[o++] = 13;                                     /* SSH_AGENTC_SIGN_REQUEST */
    put_str(out, &o, kb, kl);
    put_str(out, &o, data, n);
    put_u32(out, &o, 0);
    size_t z = 0; put_u32(out, &z, (uint32_t)(o - 4));
    return o;
}

int agent_sign_resp(const uint8_t *r, size_t n, uint8_t sig[64])
{
    /* 14(SSH_AGENT_SIGN_RESPONSE) + string( string "ssh-ed25519" + string(64) ) */
    if (n != 1 + 4 + 4 + 11 + 4 + 64 || r[0] != 14) return -1;
    if (memcmp(r + 5, "\0\0\0\x0bssh-ed25519\0\0\0\x40", 19)) return -1;
    memcpy(sig, r + 5 + 19, 64);
    return 0;
}

/* 放进主钥匙(带有效期): SSH2_AGENTC_ADD_ID_CONSTRAINED(25) + 有效期约束(1) */
size_t agent_add_req(const uint8_t seed[32], const uint8_t pub[32], const char *comment, uint32_t life_s, uint8_t *out, size_t cap)
{
    size_t o = 4, cl = strlen(comment);
    uint8_t sk[64];
    if (cap < 4 + 1 + 4 + 11 + 4 + 32 + 4 + 64 + 4 + cl + 1 + 4) return 0;
    memcpy(sk, seed, 32); memcpy(sk + 32, pub, 32);
    out[o++] = life_s ? 25 : 17;                         /* 25 带时限; 17 不带(永久, 直到上锁或 ssh-agent 退出) */
    put_str(out, &o, "ssh-ed25519", 11); put_str(out, &o, pub, 32); put_str(out, &o, sk, 64); put_str(out, &o, comment, cl);
    if (life_s) { out[o++] = 1; put_u32(out, &o, life_s); }
    memset(sk, 0, sizeof sk);
    size_t z = 0; put_u32(out, &z, (uint32_t)(o - 4));
    return o;
}

size_t agent_remove_req(const uint8_t pub[32], uint8_t *out, size_t cap)   /* SSH2_AGENTC_REMOVE_IDENTITY(18) */
{
    uint8_t kb[51]; size_t o = 4, kl = ssh_keyblob(pub, kb);
    if (cap < 4 + 1 + 4 + kl) return 0;
    out[o++] = 18; put_str(out, &o, kb, kl);
    size_t z = 0; put_u32(out, &z, (uint32_t)(o - 4));
    return o;
}

size_t agent_list_req(uint8_t *out, size_t cap)                           /* SSH2_AGENTC_REQUEST_IDENTITIES(11) */
{
    if (cap < 5) return 0;
    out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 1; out[4] = 11;
    return 5;
}

int agent_list_has(const uint8_t *r, size_t n, const uint8_t pub[32])     /* 回答(12)里有没有这把公钥 */
{
    uint8_t kb[51]; size_t kl = ssh_keyblob(pub, kb), o = 5;
    if (n < 5 || r[0] != 12) return 0;
    uint32_t cnt = (uint32_t)r[1] << 24 | (uint32_t)r[2] << 16 | (uint32_t)r[3] << 8 | r[4];
    for (uint32_t i = 0; i < cnt; i++) {
        for (int f = 0; f < 2; f++) {
            if (o + 4 > n) return 0;
            uint32_t l = (uint32_t)r[o] << 24 | (uint32_t)r[o + 1] << 16 | (uint32_t)r[o + 2] << 8 | r[o + 3];
            o += 4;
            if (o + l > n) return 0;
            if (f == 0 && l == kl && !memcmp(r + o, kb, kl)) return 1;
            o += l;
        }
    }
    return 0;
}
