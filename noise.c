/* Noise_IK_25519_ChaChaPoly_BLAKE2b(Noise 规范 rev34)
 *   IK:  <- s          (发起方事先知道应答方静态公钥)
 *        -> e, es, s, ss
 *        <- e, ee, se
 * ChaChaPoly 按 RFC 8439 自己拼(Monocypher 的 crypto_aead_write 每条消息换钥, 不是 Noise 要的);
 * HMAC-BLAKE2b 块长 128; 算法全部来自 Monocypher, 不自己写原语 */
#include "mesh.h"
#include "vendor/monocypher.h"
#include "vendor/monocypher-ed25519.h"
#include <stdio.h>
#include <string.h>

#define HL 64
static const char PROTO[] = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
static const char PROLOGUE[] = "custhub-mesh-1";

static void hmac(uint8_t out[HL], const uint8_t key[HL],
                 const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    uint8_t pad[128], inner[HL];
    crypto_blake2b_ctx c;
    memset(pad, 0x36, sizeof pad); for (int i = 0; i < HL; i++) pad[i] ^= key[i];
    crypto_blake2b_init(&c, HL); crypto_blake2b_update(&c, pad, 128);
    crypto_blake2b_update(&c, a, an); crypto_blake2b_update(&c, b, bn); crypto_blake2b_final(&c, inner);
    memset(pad, 0x5c, sizeof pad); for (int i = 0; i < HL; i++) pad[i] ^= key[i];
    crypto_blake2b_init(&c, HL); crypto_blake2b_update(&c, pad, 128);
    crypto_blake2b_update(&c, inner, HL); crypto_blake2b_final(&c, out);
    crypto_wipe(pad, sizeof pad); crypto_wipe(inner, sizeof inner);
}

static void hkdf2(const uint8_t ck[HL], const uint8_t *ikm, size_t n, uint8_t o1[HL], uint8_t o2[HL])
{
    uint8_t t[HL], one = 1, two = 2;
    hmac(t, ck, ikm, n, NULL, 0);
    hmac(o1, t, &one, 1, NULL, 0);
    hmac(o2, t, o1, HL, &two, 1);
    crypto_wipe(t, sizeof t);
}

static void nonce12(uint8_t nn[12], uint64_t n)
{
    memset(nn, 0, 4);
    for (int i = 0; i < 8; i++) nn[4 + i] = (uint8_t)(n >> (8 * i));
}

static void le64(uint8_t o[8], uint64_t v) { for (int i = 0; i < 8; i++) o[i] = (uint8_t)(v >> (8 * i)); }

static void poly(uint8_t tag[16], const uint8_t pk[32], const uint8_t *ad, size_t adn, const uint8_t *c, size_t cn)
{
    static const uint8_t z[16];
    uint8_t lens[16];
    crypto_poly1305_ctx p;
    crypto_poly1305_init(&p, pk);
    crypto_poly1305_update(&p, ad, adn); crypto_poly1305_update(&p, z, (16 - adn % 16) % 16);
    crypto_poly1305_update(&p, c, cn);   crypto_poly1305_update(&p, z, (16 - cn % 16) % 16);
    le64(lens, adn); le64(lens + 8, cn);
    crypto_poly1305_update(&p, lens, 16);
    crypto_poly1305_final(&p, tag);
}

/* RFC 8439 AEAD; out 长度 n+16 */
static void seal(const uint8_t k[32], uint64_t n, const uint8_t *ad, size_t adn,
                 const uint8_t *p, size_t pn, uint8_t *out)
{
    uint8_t nn[12], blk[64] = {0}, pk[64];
    nonce12(nn, n);
    crypto_chacha20_ietf(pk, blk, 64, k, nn, 0);
    crypto_chacha20_ietf(out, p, pn, k, nn, 1);
    poly(out + pn, pk, ad, adn, out, pn);
    crypto_wipe(pk, sizeof pk);
}

static int unseal(const uint8_t k[32], uint64_t n, const uint8_t *ad, size_t adn,
                  const uint8_t *c, size_t cn, uint8_t *out)
{
    if (cn < 16) return -1;
    uint8_t nn[12], blk[64] = {0}, pk[64], tag[16];
    nonce12(nn, n);
    crypto_chacha20_ietf(pk, blk, 64, k, nn, 0);
    poly(tag, pk, ad, adn, c, cn - 16);
    crypto_wipe(pk, sizeof pk);
    if (crypto_verify16(tag, c + cn - 16)) return -1;
    crypto_chacha20_ietf(out, c, cn - 16, k, nn, 1);
    return 0;
}

static void mixhash(hs_t *h, const uint8_t *d, size_t n)
{
    crypto_blake2b_ctx c;
    crypto_blake2b_init(&c, HL); crypto_blake2b_update(&c, h->h, HL);
    crypto_blake2b_update(&c, d, n); crypto_blake2b_final(&c, h->h);
}

static void mixkey(hs_t *h, const uint8_t ikm[32])
{
    uint8_t o1[HL], o2[HL];
    hkdf2(h->ck, ikm, 32, o1, o2);
    memcpy(h->ck, o1, HL); memcpy(h->k, o2, 32); h->hask = 1; h->n = 0;
    crypto_wipe(o1, HL); crypto_wipe(o2, HL);
}

static void dh(hs_t *h, const uint8_t sec[32], const uint8_t pub[32])
{
    uint8_t s[32];
    crypto_x25519(s, sec, pub);
    mixkey(h, s);
    crypto_wipe(s, 32);
}

static size_t enc_hash(hs_t *h, const uint8_t *p, size_t n, uint8_t *out)
{
    size_t on = n;
    if (h->hask) { seal(h->k, h->n++, h->h, HL, p, n, out); on += 16; }
    else memmove(out, p, n);
    mixhash(h, out, on);
    return on;
}

static long dec_hash(hs_t *h, const uint8_t *c, size_t n, uint8_t *out)
{
    uint8_t hh[HL];
    memcpy(hh, h->h, HL);
    mixhash(h, c, n);
    if (!h->hask) { memmove(out, c, n); return (long)n; }
    if (n < 16 || unseal(h->k, h->n++, hh, HL, c, n, out)) return -1;
    return (long)(n - 16);
}

static void split(hs_t *h, cs_t *tx, cs_t *rx)
{
    uint8_t o1[HL], o2[HL];
    hkdf2(h->ck, NULL, 0, o1, o2);
    cs_t a = { {0}, 0 }, b = { {0}, 0 };
    memcpy(a.k, o1, 32); memcpy(b.k, o2, 32);
    if (h->initiator) { *tx = a; *rx = b; } else { *tx = b; *rx = a; }
    crypto_wipe(o1, HL); crypto_wipe(o2, HL); crypto_wipe(&a, sizeof a); crypto_wipe(&b, sizeof b);
    crypto_wipe(h->e_sec, 32); crypto_wipe(h->ck, HL); crypto_wipe(h->k, 32);
}

void hs_init(hs_t *h, int initiator, const uint8_t s_sec[32], const uint8_t s_pub[32], const uint8_t rs[32])
{
    memset(h, 0, sizeof *h);
    h->initiator = initiator;
    memcpy(h->h, PROTO, sizeof PROTO - 1);      /* 33 字节 ≤ 64: 补零即可 */
    memcpy(h->ck, h->h, HL);
    memcpy(h->s_sec, s_sec, 32); memcpy(h->s_pub, s_pub, 32);
    mixhash(h, (const uint8_t *)PROLOGUE, sizeof PROLOGUE - 1);
    if (initiator) { memcpy(h->rs, rs, 32); mixhash(h, rs, 32); }
    else mixhash(h, s_pub, 32);
}

static void gen_e(hs_t *h)
{
    rnd(h->e_sec, 32);
    crypto_x25519_public_key(h->e_pub, h->e_sec);
}

long hs_write1(hs_t *h, const uint8_t *pl, size_t pn, uint8_t *out)
{
    size_t o = 0;
    gen_e(h);
    memcpy(out, h->e_pub, 32); mixhash(h, h->e_pub, 32); o = 32;
    dh(h, h->e_sec, h->rs);                         /* es */
    o += enc_hash(h, h->s_pub, 32, out + o);        /* s */
    dh(h, h->s_sec, h->rs);                         /* ss */
    o += enc_hash(h, pl, pn, out + o);
    return (long)o;
}

long hs_read1(hs_t *h, const uint8_t *in, size_t n, uint8_t *pl, size_t pcap)
{
    if (n < 32 + 48 + 16 || n - 96 > pcap) return -1;
    memcpy(h->re, in, 32); mixhash(h, h->re, 32);
    dh(h, h->s_sec, h->re);                         /* es */
    if (dec_hash(h, in + 32, 48, h->rs) != 32) return -1;
    dh(h, h->s_sec, h->rs);                         /* ss */
    return dec_hash(h, in + 80, n - 80, pl);
}

long hs_write2(hs_t *h, const uint8_t *pl, size_t pn, uint8_t *out, cs_t *tx, cs_t *rx)
{
    size_t o;
    gen_e(h);
    memcpy(out, h->e_pub, 32); mixhash(h, h->e_pub, 32); o = 32;
    dh(h, h->e_sec, h->re);                         /* ee */
    dh(h, h->e_sec, h->rs);                         /* se */
    o += enc_hash(h, pl, pn, out + o);
    split(h, tx, rx);
    return (long)o;
}

long hs_read2(hs_t *h, const uint8_t *in, size_t n, uint8_t *pl, size_t pcap, cs_t *tx, cs_t *rx)
{
    if (n < 32 + 16 || n - 48 > pcap) return -1;
    memcpy(h->re, in, 32); mixhash(h, h->re, 32);
    dh(h, h->e_sec, h->re);                         /* ee */
    dh(h, h->s_sec, h->re);                         /* se */
    long r = dec_hash(h, in + 32, n - 32, pl);
    if (r < 0) return -1;
    split(h, tx, rx);
    return r;
}

long cs_seal(cs_t *c, const uint8_t *p, size_t n, uint8_t *out)
{
    seal(c->k, c->n++, NULL, 0, p, n, out);
    return (long)(n + 16);
}

long cs_open(cs_t *c, const uint8_t *in, size_t n, uint8_t *out)
{
    if (n < 16 || unseal(c->k, c->n, NULL, 0, in, n, out)) return -1;
    c->n++;
    return (long)(n - 16);
}

/* ---------- 身份: ed25519 种子; Noise 用由它推出的 x25519 ---------- */
void ed_to_x(const uint8_t ed[32], uint8_t x[32]) { crypto_eddsa_to_x25519(x, ed); }

static int ident_from_seed(ident_t *id)
{
    uint8_t seed[32], hsh[64];
    memcpy(seed, id->seed, 32);
    crypto_ed25519_key_pair(id->edsk, id->ed, seed);        /* 会擦掉 seed 副本 */
    crypto_sha512(hsh, id->seed, 32);
    memcpy(id->xsec, hsh, 32);                               /* x25519 自己会钳位 */
    crypto_wipe(hsh, sizeof hsh);
    crypto_x25519_public_key(id->x, id->xsec);
    uint8_t chk[32]; ed_to_x(id->ed, chk);
    return crypto_verify32(chk, id->x) ? -1 : 0;             /* 两条路推出的 x25519 公钥必须一致 */
}

int ident_load(const char *path, ident_t *id)
{
    char t[128];
    if (m_read(path, t, sizeof t) < 64) return -1;
    for (int i = 0; i < 32; i++) { unsigned v; if (sscanf(t + 2 * i, "%2x", &v) != 1) return -1; id->seed[i] = (uint8_t)v; }
    return ident_from_seed(id);
}

int ident_new(const char *path, ident_t *id)
{
    char t[80];
    rnd(id->seed, 32);
    for (int i = 0; i < 32; i++) snprintf(t + 2 * i, 3, "%02x", id->seed[i]);
    t[64] = '\n';
    if (ident_from_seed(id) || m_write(path, t, 65)) return -1;
    return 0;
}
