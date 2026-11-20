/* 小工具: 缓冲、base64、文件、日志(系统相关的在平台模块) */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

int buf_add(buf_t *b, const void *d, size_t n)
{
    if (b->len + n > b->cap) {
        size_t c = b->cap ? b->cap : 4096;
        while (c < b->len + n) c *= 2;
        uint8_t *p = realloc(b->p, c);
        if (!p) return -1;
        b->p = p; b->cap = c;
    }
    memcpy(b->p + b->len, d, n); b->len += n;
    return 0;
}

void buf_eat(buf_t *b, size_t n)
{
    if (n >= b->len) { b->len = 0; return; }
    memmove(b->p, b->p + n, b->len - n); b->len -= n;
}

void buf_free(buf_t *b) { free(b->p); b->p = NULL; b->len = b->cap = 0; }


/* 日志: conf 里给了 log 就写文件(超过 1MB 换到 .1), 否则 stderr */
static FILE *logfp;
void log_open(const char *path)
{
    char old[600];
    FILE *f = fopen(path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f); fclose(f);
        if (sz > 1024 * 1024) { snprintf(old, sizeof old, "%s.1", path); remove(old); rename(path, old); }
    }
    logfp = fopen(path, "ab");
}

void logf_(const char *fmt, ...)
{
    if (!logfp && G.quiet) return;
    FILE *o = logfp ? logfp : stderr;
    int64_t w = wall_ms();
    time_t t = (time_t)(w / 1000);
    struct tm *tm = localtime(&t);
    if (tm) fprintf(o, "%02d-%02d %02d:%02d:%02d.%03ld ", tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, (long)(w % 1000));
    fprintf(o, "[%s] ", G.name[0] ? G.name : "-");
    va_list ap; va_start(ap, fmt); vfprintf(o, fmt, ap); va_end(ap);
    fputc('\n', o);
    fflush(o);
}


void b64_encode(const uint8_t *in, size_t n, char *out)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        out[o++] = T[v >> 18 & 63]; out[o++] = T[v >> 12 & 63];
        out[o++] = i + 1 < n ? T[v >> 6 & 63] : '=';
        out[o++] = i + 2 < n ? T[v & 63] : '=';
    }
    out[o] = 0;
}

long m_read(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    int more = fgetc(f) != EOF;
    fclose(f);
    if (more) return -2;
    buf[n] = 0;
    return (long)n;
}

int m_write(const char *path, const char *data, size_t len)
{
    char tmp[600];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    int ok = fwrite(data, 1, len, f) == len;
    ok = (fclose(f) == 0) && ok;
    if (ok && p_replace(tmp, path)) ok = 0;
    if (!ok) { remove(tmp); return -1; }
    return 0;
}

int ssh_pub(const char *line, uint8_t pub[32])
{
    const char *p = strstr(line, "ssh-ed25519 ");
    if (!p) return -1;
    p += 12;
    size_t n = strcspn(p, " \r\n");
    uint8_t w[64];
    if (b64_decode(p, n, w, sizeof w) != 51 || memcmp(w, "\0\0\0\x0bssh-ed25519\0\0\0\x20", 19)) return -1;
    memcpy(pub, w + 19, 32);
    return 0;
}

int hostport(const char *s, char *host, size_t hcap, int *port)   /* "主机:端口" 或 "[IPv6]:端口" */
{
    const char *c;
    if (s[0] == '[') {
        const char *e = strchr(s, ']');
        if (!e || e[1] != ':' || (size_t)(e - s - 1) >= hcap || e == s + 1) return -1;
        memcpy(host, s + 1, (size_t)(e - s - 1)); host[e - s - 1] = 0;
        c = e + 1;
    } else {
        c = strrchr(s, ':');
        if (!c || (size_t)(c - s) >= hcap || c == s) return -1;
        memcpy(host, s, (size_t)(c - s)); host[c - s] = 0;
    }
    char *e; long p = strtol(c + 1, &e, 10);
    if (*e || p <= 0 || p > 65535) return -1;
    *port = (int)p;
    return 0;
}

char *m_tok(char *s, const char *delim, char **save)
{
    if (!s) s = *save;
    if (!s) return NULL;
    s += strspn(s, delim);
    if (!*s) { *save = NULL; return NULL; }
    char *e = s + strcspn(s, delim);
    if (*e) { *e = 0; *save = e + 1; } else *save = NULL;
    return s;
}

void short_id(const uint8_t pub[32], char out[9])
{
    for (int i = 0; i < 4; i++) snprintf(out + 2 * i, 3, "%02x", pub[i]);
}

void json_str(buf_t *o, const char *s)
{
    buf_add(o, "\"", 1);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        char e[8]; const char *r = NULL;
        if (*p == '"') r = "\\\""; else if (*p == '\\') r = "\\\\"; else if (*p == '\n') r = "\\n"; else if (*p == '\r') r = "\\r"; else if (*p == '\t') r = "\\t";
        else if (*p < 0x20) { snprintf(e, sizeof e, "\\u%04x", *p); r = e; }
        if (r) buf_add(o, r, strlen(r)); else buf_add(o, p, 1);
    }
    buf_add(o, "\"", 1);
}
