# astrbot_plugin_netkit

AstrBot 网络工具集插件 (NetKit). 短期目标: IP/ASN 等信息查询; 长期目标: 加入 ping、dns、whois 等基础诊断命令.

版本变更见 [CHANGELOG.md](CHANGELOG.md).

## 功能

- `/ip` 支持 IPv4, IPv6, 域名以及 URL / `host:port` 形式
  - 输入会先经 `urllib.parse.urlsplit` 提取 host (剥离 scheme / port / path / query / `[]` 包裹)
  - 域名解析采用 **多 DoH 视角聚合**: 系统解析器 + 9 个公共 DoH 端点 (Google / AliDNS / AdGuard / DNS.SB / DNSPod / NextDNS / 360 / LibreDNS / Tiarap) 并发查询, 同时支持 RFC 8427 (JSON) 与 RFC 8484 (wire format), 单端点 3s 超时, 聚合后去重。这能发现动态分配域名 (机场代理, Azure Front Door 等) 真正的多个节点 IP
  - 进一步在 Google JSON DoH 上注入 **EDNS Client Subnet (RFC 7871) 探测** (CN-CT / CN-CU / CN-CM / CN-EDU / HK / TW 6 个代表性 /24 网段), 强制权威 DNS 按那个 client subnet 分流, 以发现按运营商/地区做 GeoDNS 分流时仅特定网段才能看到的 IP
  - 首个 IP 走 [ip-api.com](https://ip-api.com/) 拿全字段中文详细信息; 后续 IP 并发查询 [ipwho.is](https://ipwho.is/) 拿精简一行 (运营商, 国家/地区/城市); 默认最多展示前 10 个
  - 私有地址 / 回环 / 链路本地 / 组播等保留地址会本地拒绝, 解析后的 IP 也会再次校验, 防止 `https://localhost` 等绕过
- `/asn` 查询 ASN 归属与 RIR 信息, 输入接受三类形式:
  - **ASN 编号**: `AS13335` / `as13335` / `13335`
  - **IP 字面量**: `47.238.146.96` / `2001:4860:4860::8888` (先经 RIPEstat `network-info` 反查 ASN)
  - **域名 / URL**: `https://api.bgpview.io:443` / `https://www.cloudflare.com/foo?x=1` (异步 DNS 解析为 IP, 解析后的 IP 再次经过保留段判断, 防止误查内网)
  - 私有 ASN (64512–65534, 4200000000–4294967294) 与文档/保留段会本地拒绝
- `/iphist` 单独查询域名的 **passive DNS 历史 IP**
  - 数据来自 [AlienVault OTX](https://otx.alienvault.com/), 免费无 key
  - 返回该 host 历史出现过的 A / AAAA 记录, 含国家 / ASN / 首见 / 最近 时间戳, 按 `last` 倒序最多 20 条
  - 动态分配 / 短期域名通常 0 records; 高流量域名响应可能 10–25s, 单独 30s 超时窗口
- 超时和网络错误均给出友好提示

## 使用

在任意会话发送:

```
/ip 1.1.1.1
/ip 38.76.141.233:28367
/ip 2001:4860:4860::8888
/ip example.com
/ip https://www.cloudflare.com:443/foo

/asn AS13335
/asn 47.238.146.96
/asn https://1.1.1.1
/asn https://api.bgpview.io:443

/iphist www.cloudflare.com
/iphist https://github.com
```

无参数时插件会回复用法说明.

## 示例回复

```
查询地址: one.one.one.one
IP: 1.0.0.1
国家: 澳大利亚
地区: 昆士兰州
城市: 南布里斯班
归属: 澳大利亚 昆士兰州 南布里斯班
运营商/ISP: Cloudflare, Inc.
组织: APNIC and Cloudflare DNS Resolver project
ASN: AS13335 Cloudflare, Inc.
时区: Australia/Brisbane
经纬度: -27.4766, 153.0166

— 另解析到 3 个 IP（数据源 ipwho.is）—
1.1.1.1 — Cloudflare, Inc. (Australia, Queensland, Brisbane)
2606:4700:4700::1001 — Cloudflare, Inc. (United States, ...)
2606:4700:4700::1111 — Cloudflare, Inc. (United States, ...)
```

```
查询 ASN: AS45102 (来自 47.238.146.96)
名称: ALIBABA-CN-NET
描述: Alibaba (US) Technology Co., Ltd.
国家: US
RIR: APNIC
是否公告: 是
数据源: RIPEstat
```

```
DNS 历史 — www.cloudflare.com
数据源: AlienVault OTX (passive DNS)
共 25 条 A/AAAA 记录，仅显示最近 20 条

  104.16.124.96
    United States | AS13335 cloudflare
    首见 2020-11-05, 最近 2026-05-04
  104.16.123.96
    United States | AS13335 cloudflare
    首见 2020-11-05, 最近 2026-05-04
  ...
```

## 数据来源

- IP 归属 (首个 IP 详细): [ip-api.com](https://ip-api.com/) `/json/<query>?lang=zh-CN`
  - 免费额度: 45 次/分钟, 仅 HTTP
- IP 归属 (其余 IP 精简): [ipwho.is](https://ipwho.is/) `/<ip>`
  - 免费、无需 key, 走 HTTPS, 官方声明无配额限制
- DNS 多视角解析: 9 个公共 DoH 端点 (Google / AliDNS / AdGuard / DNS.SB / DNSPod / NextDNS / 360 / LibreDNS / Tiarap)
  - 同时实现 JSON DoH 与 RFC 8484 wire-format DoH, 兼容只支持其中一种的端点
  - 在 Google JSON DoH 上额外注入 EDNS Client Subnet (RFC 7871) 探测 6 个代表性网段, 覆盖 GeoDNS 按运营商/地区分流的场景
  - 设计参考 [amass](https://github.com/owasp-amass/amass) 等子域枚举工具的 multi-resolver 思路
- ASN 归属: [RIPEstat](https://stat.ripe.net/) `as-overview` + `whois` 端点合并;  IP→ASN 反查走 `network-info` 端点
  - 免费、无需 key, 走 HTTPS
  - 不同 RIR 字段命名有差异 (APNIC: `as-name`/`descr`/`country`; ARIN: `OrgName`/`Country`); 名称与描述统一回退到 overview 的 `holder` 字段拆解
- Passive DNS 历史: [AlienVault OTX](https://otx.alienvault.com/) `/api/v1/indicators/hostname/<host>/passive_dns`
  - 免费、无需 key, 走 HTTPS
  - 仅对静态 / 高流量域名有用; 动态分配 / 短期域名通常 0 records

## 安装

将本目录放入 AstrBot 的插件目录, 安装依赖后重启 AstrBot:

```
pip install -r requirements.txt
```

## 许可

MIT, 见 [LICENSE](LICENSE).
