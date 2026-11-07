# custhub

客户远程维护接入中枢。任意一台 Debian/Ubuntu 公网机, 在服务器上以 root 粘贴一条命令即装好, 装完自动加入中枢池。

- 一键命令由维护端生成(内含池密钥和维护端公钥, 不在本仓库); 命令按固定版本拉取本仓库文件, 逐个校验 sha256
- 拉取顺序: api.github.com → raw.githubusercontent.com → jsDelivr → ghfast.top → gh-proxy.com
- 卸载: `/usr/local/lib/custhub/uninstall.sh`; 也可在维护端「管理中枢」里远程升级/卸载
- 需要放行: UDP 51820(WireGuard)、TCP 8443(下发/回报/组池)
