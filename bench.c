/* 测速服务(custhub bench): 对方开 "bench:up" = 收下就扔(测上传), "bench:dn:<秒>" = 尽力发零字节, 到点关(测下载)
 *   权限和 shell 一样(能开 sh 的才能测, 免得谁都能拿它灌流量); 数据走的就是平常的流(同样的加密、额度、选路), 测出来就是实际能用的速度 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXB 8
static struct { int used, fd, src; int64_t end; } B[MAXB];

int bench_accept(const char *req, char *why, size_t wcap)
{
    int src = !strncmp(req, "bench:dn:", 9), secs = src ? atoi(req + 9) : 0;
    if (!src && strcmp(req, "bench:up")) { snprintf(why, wcap, "不认识的测速请求"); return -1; }
    if (src && (secs < 1 || secs > 60)) { snprintf(why, wcap, "测速时长要 1~60 秒"); return -1; }
    for (int k = 0; k < MAXB; k++) if (!B[k].used) {
        int sp[2];
        if (p_pair(sp)) { snprintf(why, wcap, "开不了测速通道"); return -1; }
        B[k].used = 1; B[k].fd = sp[1]; B[k].src = src; B[k].end = now_ms() + (int64_t)secs * 1000;
        return sp[0];
    }
    snprintf(why, wcap, "测速的太多了");
    return -1;
}

static void bclose(int k) { p_close(B[k].fd); B[k].used = 0; }

void bench_poll_add(pfd_t *p, int *np, int *map)
{
    for (int k = 0; k < MAXB; k++) if (B[k].used) { p[*np].fd = B[k].fd; p[*np].ev = (short)(B[k].src ? P_IN | P_OUT : P_IN); map[(*np)++] = 7000 + k; }
}

void bench_io(int k, short rev)
{
    static uint8_t z[65536];
    if (k < 0 || k >= MAXB || !B[k].used) return;
    if (rev & (P_IN | P_HUP)) {                          /* 上传: 收下就扔; 下载方关了也在这里看到 */
        long r = p_recv(B[k].fd, z, sizeof z);
        if (r == 0 || r == P_FAIL) { bclose(k); return; }
    }
    if (B[k].src && (rev & P_OUT)) {
        if (now_ms() >= B[k].end) { p_shut_wr(B[k].fd); B[k].src = 0; return; }   /* 到点: 半关, 等对方关 */
        memset(z, 0, sizeof z);
        long w = p_send(B[k].fd, z, sizeof z);
        if (w == P_FAIL) bclose(k);
    }
}

void bench_tick(void)
{
    int64_t now = now_ms();
    for (int k = 0; k < MAXB; k++) if (B[k].used && now > B[k].end + 120000) bclose(k);   /* 兜底: 谁都不关的, 两分钟后收 */
}
