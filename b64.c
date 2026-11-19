/* base64 解码: 只在单独编 mesh 时链进来; 并进 custhub 时用 src/client/util.c 那份(同语义, sshsig.c 要用) */
#include "mesh.h"

static int b64v(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* 与 src/client/util.c 同语义(sshsig.c 要用): 跳过空白, '=' 结束, 其他非法字符拒 */
long b64_decode(const char *in, size_t inlen, uint8_t *out, size_t cap)
{
    uint32_t acc = 0; int bits = 0; size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        int c = (unsigned char)in[i];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        if (c == '=') break;
        int v = b64v(c);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v; bits += 6;
        if (bits >= 8) { bits -= 8; if (o >= cap) return -1; out[o++] = (uint8_t)(acc >> bits); }
    }
    return (long)o;
}
