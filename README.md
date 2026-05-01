# astrbot_plugin_ipquery

AstrBot 插件: 查询 IPv4 / IPv6 / 域名的归属地信息, 返回中文格式的摘要.

## 功能

- 支持 IPv4, IPv6 与域名 (域名会被自动解析为 IP)
- 中文输出: 国家, 地区, 城市, 运营商/ISP, 组织, ASN, 时区, 经纬度
- 私有地址 / 回环 / 链路本地 / 组播等保留地址会本地拒绝, 不向上游发送请求
- 超时和网络错误均给出友好提示

## 使用

在任意会话发送:

```
/ip 1.1.1.1
/ip 2001:4860:4860::8888
/ip example.com
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

## 数据来源

- 上游 API: [ip-api.com](https://ip-api.com/) 的 `/json/<query>?lang=zh-CN` 端点
- 免费额度: 45 次/分钟 (按调用方源 IP 计)
- 已知限制: 免费版仅提供 HTTP 端点, 不支持 HTTPS

## 安装

将本目录放入 AstrBot 的插件目录, 安装依赖后重启 AstrBot:

```
pip install -r requirements.txt
```

## 许可

MIT, 见 [LICENSE](LICENSE).
