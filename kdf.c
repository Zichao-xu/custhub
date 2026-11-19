/* 口令派生(design-v3 §0 第 18 条: 解锁搬进 C, 和 passkey.py 完全相同, 主钥匙不变)
 *   口令 → 规整(转小写、空白合成一个空格、去头尾) → scrypt(N=2^17, r=8, p=1, 盐 "custhub-mesh-v1/<用途>", 32 字节) → ed25519 种子
 *   scrypt 要 SHA-256(Monocypher 没有): 这里按 FIPS 180-4 写一份, 连同 HMAC-SHA256、PBKDF2、Salsa20/8(RFC 7914)
 *   内存: 128 × r × N = 128 MB, 只在管理端解锁时用 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- SHA-256 ---------- */
typedef struct { uint32_t h[8]; uint8_t b[64]; size_t n; uint64_t len; } sha256_t;
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(sha256_t *s, const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3), s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha_init(sha256_t *s)
{
    static const uint32_t H0[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(s->h, H0, sizeof H0); s->n = 0; s->len = 0;
}

static void sha_update(sha256_t *s, const uint8_t *p, size_t n)
{
    s->len += n;
    while (n) {
        size_t k = 64 - s->n < n ? 64 - s->n : n;
        memcpy(s->b + s->n, p, k); s->n += k; p += k; n -= k;
        if (s->n == 64) { sha_block(s, s->b); s->n = 0; }
    }
}

static void sha_final(sha256_t *s, uint8_t out[32])
{
    uint64_t bits = s->len * 8;
    uint8_t pad = 0x80, z = 0, L8[8];
    sha_update(s, &pad, 1);
    while (s->n != 56) sha_update(s, &z, 1);
    for (int i = 0; i < 8; i++) L8[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(s, L8, 8);
    for (int i = 0; i < 8; i++) { out[4 * i] = (uint8_t)(s->h[i] >> 24); out[4 * i + 1] = (uint8_t)(s->h[i] >> 16); out[4 * i + 2] = (uint8_t)(s->h[i] >> 8); out[4 * i + 3] = (uint8_t)s->h[i]; }
}

/* ---------- HMAC-SHA256 / PBKDF2 ---------- */
typedef struct { sha256_t in, out; } hmac_t;

static void hmac_init(hmac_t *h, const uint8_t *key, size_t kn)
{
    uint8_t k[64] = { 0 }, pad[64];
    if (kn > 64) { sha256_t s; sha_init(&s); sha_update(&s, key, kn); sha_final(&s, k); } else memcpy(k, key, kn);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha_init(&h->in); sha_update(&h->in, pad, 64);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    sha_init(&h->out); sha_update(&h->out, pad, 64);
}

static void hmac_final(hmac_t *h, uint8_t out[32])
{
    uint8_t d[32];
    sha_final(&h->in, d); sha_update(&h->out, d, 32); sha_final(&h->out, out);
}

static void pbkdf2_1(const uint8_t *pw, size_t pn, const uint8_t *salt, size_t sn, uint8_t *out, size_t dk)   /* 迭代 1 次(scrypt 只要这个) */
{
    hmac_t base; hmac_init(&base, pw, pn);
    for (uint32_t blk = 1; dk; blk++) {
        hmac_t h = base; uint8_t be[4] = { (uint8_t)(blk >> 24), (uint8_t)(blk >> 16), (uint8_t)(blk >> 8), (uint8_t)blk }, t[32];
        sha_update(&h.in, salt, sn); sha_update(&h.in, be, 4); hmac_final(&h, t);
        size_t k = dk < 32 ? dk : 32;
        memcpy(out, t, k); out += k; dk -= k;
    }
}

/* ---------- scrypt(RFC 7914) ---------- */
#define R32(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
static void salsa8(uint32_t B[16])
{
    uint32_t x[16];
    memcpy(x, B, 64);
    for (int i = 0; i < 8; i += 2) {
        x[4] ^= R32(x[0] + x[12], 7);  x[8] ^= R32(x[4] + x[0], 9);   x[12] ^= R32(x[8] + x[4], 13);  x[0] ^= R32(x[12] + x[8], 18);
        x[9] ^= R32(x[5] + x[1], 7);   x[13] ^= R32(x[9] + x[5], 9);  x[1] ^= R32(x[13] + x[9], 13);  x[5] ^= R32(x[1] + x[13], 18);
        x[14] ^= R32(x[10] + x[6], 7); x[2] ^= R32(x[14] + x[10], 9); x[6] ^= R32(x[2] + x[14], 13);  x[10] ^= R32(x[6] + x[2], 18);
        x[3] ^= R32(x[15] + x[11], 7); x[7] ^= R32(x[3] + x[15], 9);  x[11] ^= R32(x[7] + x[3], 13);  x[15] ^= R32(x[11] + x[7], 18);
        x[1] ^= R32(x[0] + x[3], 7);   x[2] ^= R32(x[1] + x[0], 9);   x[3] ^= R32(x[2] + x[1], 13);   x[0] ^= R32(x[3] + x[2], 18);
        x[6] ^= R32(x[5] + x[4], 7);   x[7] ^= R32(x[6] + x[5], 9);   x[4] ^= R32(x[7] + x[6], 13);   x[5] ^= R32(x[4] + x[7], 18);
        x[11] ^= R32(x[10] + x[9], 7); x[8] ^= R32(x[11] + x[10], 9); x[9] ^= R32(x[8] + x[11], 13);  x[10] ^= R32(x[9] + x[8], 18);
        x[12] ^= R32(x[15] + x[14], 7); x[13] ^= R32(x[12] + x[15], 9); x[14] ^= R32(x[13] + x[12], 13); x[15] ^= R32(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; i++) B[i] += x[i];
}

static void blockmix(const uint32_t *B, uint32_t *Y, int r)   /* B、Y 各 32r 个字 */
{
    uint32_t X[16];
    memcpy(X, B + (2 * r - 1) * 16, 64);
    for (int i = 0; i < 2 * r; i++) {
        for (int j = 0; j < 16; j++) X[j] ^= B[i * 16 + j];
        salsa8(X);
        memcpy(Y + ((i & 1) * r + i / 2) * 16, X, 64);   /* 偶数块放前半, 奇数块放后半 */
    }
}

int scrypt_kdf(const uint8_t *pw, size_t pn, const uint8_t *salt, size_t sn, uint32_t N, int r, int p, uint8_t *out, size_t dk)
{
    size_t bl = (size_t)128 * r;                       /* 一块 128r 字节 */
    uint8_t *B = malloc(bl * (size_t)p);
    uint32_t *X = malloc(bl), *Y = malloc(bl), *V = malloc(bl * N);
    if (!B || !X || !Y || !V) { free(B); free(X); free(Y); free(V); return -1; }
    pbkdf2_1(pw, pn, salt, sn, B, bl * (size_t)p);
    size_t w = bl / 4;
    for (int k = 0; k < p; k++) {
        uint8_t *Bk = B + bl * (size_t)k;
        for (size_t i = 0; i < w; i++) X[i] = (uint32_t)Bk[4 * i] | (uint32_t)Bk[4 * i + 1] << 8 | (uint32_t)Bk[4 * i + 2] << 16 | (uint32_t)Bk[4 * i + 3] << 24;
        for (uint32_t i = 0; i < N; i++) { memcpy(V + w * i, X, bl); blockmix(X, Y, r); memcpy(X, Y, bl); }
        for (uint32_t i = 0; i < N; i++) {
            uint32_t j = X[(2 * r - 1) * 16] & (N - 1);    /* Integerify: 最后一块的第一个字(N 是 2 的幂, 低 32 位够) */
            for (size_t q = 0; q < w; q++) X[q] ^= V[w * j + q];
            blockmix(X, Y, r); memcpy(X, Y, bl);
        }
        for (size_t i = 0; i < w; i++) { Bk[4 * i] = (uint8_t)X[i]; Bk[4 * i + 1] = (uint8_t)(X[i] >> 8); Bk[4 * i + 2] = (uint8_t)(X[i] >> 16); Bk[4 * i + 3] = (uint8_t)(X[i] >> 24); }
    }
    pbkdf2_1(pw, pn, B, bl * (size_t)p, out, dk);
    memset(B, 0, bl * (size_t)p); memset(V, 0, bl * N); memset(X, 0, bl); memset(Y, 0, bl);
    free(B); free(X); free(Y); free(V);
    return 0;
}

/* 口令 → 种子(和 passkey.py 的 derive 一样); 规整后少于 8 个词返回 -1 */
int passphrase_seed(const char *phrase, const char *label, uint8_t seed[32])
{
    char n[1024]; size_t o = 0; int words = 0, in = 0;
    for (const char *c = phrase; *c && o < sizeof n - 2; c++) {
        unsigned char ch = (unsigned char)*c;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '\f') { in = 0; continue; }
        if (!in) { if (o) n[o++] = ' '; words++; in = 1; }
        n[o++] = (char)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
    }
    n[o] = 0;
    if (words < 8) return -1;
    char salt[96]; int sl = snprintf(salt, sizeof salt, "custhub-mesh-v1/%s", label);
    int r = scrypt_kdf((const uint8_t *)n, o, (const uint8_t *)salt, (size_t)sl, 1u << 17, 8, 1, seed, 32);
    memset(n, 0, sizeof n);
    return r;
}
