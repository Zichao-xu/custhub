/* UPnP 端口映射(design-v3 §0 第 14 条: 条件允许就自动在路由器上映射, 按租期续)
 *   SSDP 找路由器(239.255.255.250:1900; 测试可用环境变量 CUSTHUB_UPNP_SSDP=主机:端口 指到假路由器)
 *   → 取描述文件找 WANIPConnection / WANPPPConnection 的控制地址 → AddPortMapping(外 8444 → 本机监听端口)
 *   租期 1 小时, 半小时续一次; 路由器只认永久映射(725)就用 0; 外部端口被占(718)就往后试几个
 *   只在启动和续租时阻塞几秒(局域网内); 失败就算了, 回连测试照常做, 提示跑命令的人手动开 */
#include "mesh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct { char ctl_host[64], ctl_path[256], svc[96], lan_ip[48]; int ctl_port, ext, tried, perm; int64_t next; } U;

static int64_t env_s(const char *k, long def)
{
    const char *e = getenv(k);
    long v = e ? atol(e) : 0;
    return (v > 0 ? v : def) * (int64_t)1000;
}

static int url_split(const char *u, char *host, size_t hc, int *port, char *path, size_t pc)
{
    if (strncmp(u, "http://", 7)) return -1;
    const char *h = u + 7, *sl = strchr(h, '/');
    char hp[96]; size_t hl = sl ? (size_t)(sl - h) : strlen(h);
    if (hl >= sizeof hp) return -1;
    memcpy(hp, h, hl); hp[hl] = 0;
    snprintf(path, pc, "%s", sl ? sl : "/");
    char *c = strrchr(hp, ':');
    if (c) { *c = 0; *port = atoi(c + 1); } else *port = 80;
    snprintf(host, hc, "%s", hp);
    return *port > 0 ? 0 : -1;
}

/* 一次 HTTP/1.0 请求, 等最多 ms 毫秒; 返回状态码, 正文放 out */
static int http(const char *host, int port, const char *head, const char *body, char *out, size_t cap, int ms)
{
    char why[64];
    int fd = p_dial(host, port, 1, why, sizeof why);
    if (fd < 0) return -1;
    int64_t end = now_ms() + ms;
    pfd_t q = { fd, P_OUT, 0 };
    if (p_poll(&q, 1, ms) <= 0 || p_dial_result(fd)) { p_close(fd); return -1; }
    size_t hl = strlen(head), bl = body ? strlen(body) : 0;
    if (p_send(fd, head, hl) != (long)hl || (bl && p_send(fd, body, bl) != (long)bl)) { p_close(fd); return -1; }
    size_t n = 0;
    while (n < cap - 1) {
        int64_t left = end - now_ms();
        if (left <= 0) break;
        q.ev = P_IN; q.rev = 0;
        if (p_poll(&q, 1, (int)left) <= 0) break;
        long r = p_recv(fd, out + n, cap - 1 - n);
        if (r == P_AGAIN) continue;
        if (r <= 0) break;
        n += (size_t)r;
    }
    p_close(fd);
    out[n] = 0;
    int st = 0;
    if (sscanf(out, "HTTP/%*s %d", &st) != 1) return -1;
    char *b = strstr(out, "\r\n\r\n");
    if (b) memmove(out, b + 4, strlen(b + 4) + 1);
    return st;
}

static const char *tag_after(const char *x, const char *from, const char *tag, char *val, size_t vc)
{
    char o[48], c[48];
    snprintf(o, sizeof o, "<%s>", tag); snprintf(c, sizeof c, "</%s>", tag);
    const char *a = strstr(from, o);
    if (!a) return NULL;
    a += strlen(o);
    const char *e = strstr(a, c);
    if (!e || (size_t)(e - a) >= vc) return NULL;
    memcpy(val, a, (size_t)(e - a)); val[e - a] = 0;
    (void)x;
    return e;
}

static int discover(char *why, size_t wcap)
{
    char tgt[64] = "239.255.255.250"; int tport = 1900;
    const char *e = getenv("CUSTHUB_UPNP_SSDP");
    if (e && hostport(e, tgt, sizeof tgt, &tport)) return snprintf(why, wcap, "CUSTHUB_UPNP_SSDP 不对"), -1;
    int fd = p_udp_open();
    if (fd < 0) return snprintf(why, wcap, "开不了 UDP"), -1;
    static const char *st[] = { "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:service:WANIPConnection:1",
                                "urn:schemas-upnp-org:device:InternetGatewayDevice:2" };
    for (int i = 0; i < 3; i++) {
        char m[300]; int n = snprintf(m, sizeof m, "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: %s\r\n\r\n", st[i]);
        p_udp_sendto(fd, tgt, tport, m, (size_t)n);
        /* 多播走默认路由: 默认路由是代理的虚拟网卡(utun / TUN)时到不了局域网 → 对每个局域网网段的 .1 和本机自己再单发一次
         * (本机就是路由器时, 自己的 miniupnpd 也这样找到, 端口统一由它分配, 同一局域网不会撞) */
        char ips[16][48]; int ni = e ? 0 : p_local_ipv4s(ips, 16);
        for (int k = 0; k < ni; k++) {
            unsigned a, b2, c, d;
            if (sscanf(ips[k], "%u.%u.%u.%u", &a, &b2, &c, &d) != 4) continue;
            if (!(a == 10 || (a == 172 && b2 >= 16 && b2 < 32) || (a == 192 && b2 == 168))) continue;
            char gw[48]; snprintf(gw, sizeof gw, "%u.%u.%u.1", a, b2, c);
            p_udp_sendto(fd, gw, 1900, m, (size_t)n);
            if (strcmp(gw, ips[k])) p_udp_sendto(fd, ips[k], 1900, m, (size_t)n);
        }
    }
    char loc[300] = "", b[2048];
    int64_t end = now_ms() + 2500;
    while (!loc[0] && now_ms() < end) {
        pfd_t q = { fd, P_IN, 0 };
        if (p_poll(&q, 1, (int)(end - now_ms())) <= 0) break;
        long r = p_udp_recv(fd, b, sizeof b - 1);
        if (r <= 0) continue;
        b[r] = 0;
        for (char *l = b; l && *l; ) {
            char *nl = strstr(l, "\r\n"); if (nl) *nl = 0;
            if (!strncmp(l, "LOCATION:", 9) || !strncmp(l, "Location:", 9) || !strncmp(l, "location:", 9)) {
                const char *v = l + 9; while (*v == ' ') v++;
                snprintf(loc, sizeof loc, "%s", v);
            }
            l = nl ? nl + 2 : NULL;
        }
    }
    p_close(fd);
    if (!loc[0]) return snprintf(why, wcap, "局域网里没找到支持 UPnP 的路由器"), -1;
    char host[64], path[256]; int port;
    if (url_split(loc, host, sizeof host, &port, path, sizeof path)) return snprintf(why, wcap, "路由器给的地址不对"), -1;
    static char x[16384]; char head[512];
    snprintf(head, sizeof head, "GET %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", path, host, port);
    if (http(host, port, head, NULL, x, sizeof x, 3000) != 200) return snprintf(why, wcap, "取不到路由器的描述文件"), -1;
    static const char *svcs[] = { "urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANIPConnection:1",
                                  "urn:schemas-upnp-org:service:WANPPPConnection:1" };
    for (int i = 0; i < 3; i++) {
        const char *s = strstr(x, svcs[i]);
        char cu[256];
        if (!s || !tag_after(x, s, "controlURL", cu, sizeof cu)) continue;
        snprintf(U.svc, sizeof U.svc, "%s", svcs[i]);
        if (!strncmp(cu, "http://", 7)) { if (url_split(cu, U.ctl_host, sizeof U.ctl_host, &U.ctl_port, U.ctl_path, sizeof U.ctl_path)) continue; }
        else { snprintf(U.ctl_host, sizeof U.ctl_host, "%s", host); U.ctl_port = port; snprintf(U.ctl_path, sizeof U.ctl_path, "%s%s", cu[0] == '/' ? "" : "/", cu); }
        if (p_local_ip(U.ctl_host, U.lan_ip, sizeof U.lan_ip)) return snprintf(why, wcap, "拿不到本机局域网地址"), -1;
        return 0;
    }
    return snprintf(why, wcap, "路由器不支持端口映射(没有 WANIPConnection)"), -1;
}

static int add_map(int ext, int in, int lease, int *fault, const char *proto)
{
    static char body[2048], head[600], out[8192];
    snprintf(body, sizeof body,
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body><u:AddPortMapping xmlns:u=\"%s\"><NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort>"
        "<NewProtocol>%s</NewProtocol><NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient>"
        "<NewEnabled>1</NewEnabled><NewPortMappingDescription>custhub</NewPortMappingDescription>"
        "<NewLeaseDuration>%d</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>\r\n", U.svc, ext, proto, in, U.lan_ip, lease);
    snprintf(head, sizeof head, "POST %s HTTP/1.0\r\nHost: %s:%d\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n"
             "SOAPAction: \"%s#AddPortMapping\"\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
             U.ctl_path, U.ctl_host, U.ctl_port, U.svc, (int)strlen(body));
    int st = http(U.ctl_host, U.ctl_port, head, body, out, sizeof out, 3000);
    char code[16] = "";
    *fault = 0;
    if (st != 200 && tag_after(out, out, "errorCode", code, sizeof code)) *fault = atoi(code);
    return st == 200 ? 0 : -1;
}

/* 映射本机监听端口; 成功返回外部端口, 失败 0(why 写原因) */
static int map_now(int in, char *why, size_t wcap)
{
    if (!U.ctl_host[0] && discover(why, wcap)) return 0;
    int fault = 0, lease = U.perm ? 0 : 3600;
    for (int k = 0; k < 16; k++) {
        int ext = (U.ext ? U.ext : 8444) + (U.ext ? 0 : k);
        if (!add_map(ext, in, lease, &fault, "TCP")) { int f2 = 0; add_map(ext, in, lease, &f2, "UDP"); return ext; }   /* UDP 同一个外部端口(UDP 链路用; 不成也不影响 TCP) */
        if (fault == 725 && lease) { lease = 0; U.perm = 1; k--; continue; }   /* 只认永久映射: 记住, 续租直接用永久 */
        if ((fault != 718 && fault != 729) || U.ext) break;          /* 718 被别的映射占了 / 729 被路由器自己用着(比如路由器上也跑着本程序): 换下一个 */
    }
    U.ctl_host[0] = 0;                                               /* 下次重新找 */
    snprintf(why, wcap, fault ? "路由器拒绝映射(错误 %d)" : "路由器没回应映射请求", fault);
    return 0;
}

/* 每轮调一次: 到点就映射 / 续租; 结果在 G.upnp_port(0 = 没映射) */
void upnp_reset(void) { U.next = 0; U.ctl_host[0] = 0; U.ext = 0; }

void upnp_tick(void)
{
    int64_t now = now_ms();
    if (G.relay_off || G.upnp_off || G.lfd < 0 || now < U.next) return;
    char host[64], why[96]; int in;
    if (hostport(G.lspec, host, sizeof host, &in)) return;
    if (!strcmp(host, "127.0.0.1") && !getenv("CUSTHUB_UPNP_SSDP")) { U.next = now + 3600000; return; }   /* 只听本机回环: 映射没意义 */
    int ext = map_now(in, why, sizeof why);
    if (ext) {
        if (ext != G.upnp_port) logf_("UPnP: 路由器上已把 TCP %d 映射到本机 %s:%d", ext, U.lan_ip, in);
        G.upnp_port = ext; U.ext = ext;
        U.next = now + env_s("CUSTHUB_UPNP_RENEW_S", 1800);
    } else {
        if (G.upnp_port || !U.tried) logf_("UPnP: 没映射上(%s)", why);
        G.upnp_port = 0; U.ext = 0;
        U.next = now + env_s("CUSTHUB_UPNP_RETRY_S", 1800);
    }
    snprintf(G.upnp_why, sizeof G.upnp_why, "%s", ext ? "" : why);
    U.tried = 1;
}

const char *upnp_lan_ip(void) { return U.lan_ip; }
