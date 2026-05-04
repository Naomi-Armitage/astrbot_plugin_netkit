# astrbot_plugin_netkit

AstrBot 网络工具集插件 (NetKit). 短期目标: IP/ASN 等信息查询; 长期目标: 加入 ping、dns、whois 等基础诊断命令.

## 功能

- `/ip` 支持 IPv4, IPv6 与域名 (域名会被自动解析为 IP)
  - 中文输出: 国家, 地区, 城市, 运营商/ISP, 组织, ASN, 时区, 经纬度
  - 私有地址 / 回环 / 链路本地 / 组播等保留地址会本地拒绝, 不向上游发送请求
- `/asn` 查询 ASN 归属与 RIR 信息
  - 输入支持 `AS13335` / `as13335` / `13335` 三种形式
  - 私有 ASN (64512–65534, 4200000000–4294967294) 与文档/保留段会本地拒绝
- 超时和网络错误均给出友好提示

## 使用

在任意会话发送:

```
/ip 1.1.1.1
/ip 2001:4860:4860::8888
/ip example.com

/asn AS13335
/asn 45102
```

无参数时插件会回复用法说明.

## 示例回复

```
查询地址: 1.1.1.1
IP: 1.1.1.1
国家: 澳大利亚
地区: 昆士兰州
城市: 南布里斯班
归属: 澳大利亚 昆士兰州 南布里斯班
运营商/ISP: Cloudflare, Inc.
组织: APNIC and Cloudflare DNS Resolver project
ASN: AS13335 Cloudflare, Inc.
时区: Australia/Brisbane
经纬度: -27.4766, 153.0166
```

```
查询 ASN: AS13335
名称: CLOUDFLARENET
描述: Cloudflare, Inc.
国家: US
网站: https://www.cloudflare.com
流量估算: 5-10Gbps
流量比例: Mostly Outbound
RIR: ARIN
分配日期: 2010-07-14
```

## 数据来源

- IP 归属: [ip-api.com](https://ip-api.com/) `/json/<query>?lang=zh-CN`
  - 免费额度: 45 次/分钟, 仅 HTTP
- ASN 归属: [bgpview.io](https://bgpview.io/) `/asn/<number>`
  - 免费、无需 key, 走 HTTPS

## 安装

将本目录放入 AstrBot 的插件目录, 安装依赖后重启 AstrBot:

```
pip install -r requirements.txt
```

## 许可

MIT, 见 [LICENSE](LICENSE).
