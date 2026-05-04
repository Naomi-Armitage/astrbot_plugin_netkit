# 更新日志

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [v0.2.3] - 2026-05-04

### 修复
- `/ip` 现接受 `host:port` 与完整 URL 形式，例如 `/ip 38.76.141.233:28367` 不再因为带端口被上游 ip-api 拒绝。`cmd_ip` 入口接 `_extract_host` 剥离 scheme / port / path / query / IPv6 `[]` 包裹，与 `/asn` 输入解析共用同一 helper。

### 新增
- `/ip` 处理域名解析到多个 IP 的场景：首个 IP 走 ip-api 拿全字段中文详细信息，后续 IP 并发查询 [ipwho.is](https://ipwho.is/) 拿"运营商 (国家, 地区, 城市)"精简一行。ipwho.is 官方声明免费无配额限制，且每个 IP 一次请求，避免在 CDN 域名上耗尽 ip-api 的 45 次/分钟额度。
- 多 IP 输出 cap 在前 10 条；超过的会注明"（仅显示前 10 个）"，避免 CDN 域名解析出 100+ 个 IP 时把消息撑爆。
- 新增 helper `_resolve_to_ips` 返回所有去重后的 IP 列表；`_resolve_to_ip` 改为基于它的 wrapper，不影响 `/asn` 反查链路。

### 变更
- `/ip` 用法说明扩展为 `<IPv4|IPv6|域名|URL>` 并附四条示例。
- 域名 → 多 IP 路径下，每一个解析得到的 IP 都会再次经过 `_reject_reserved_ip`（与 `/asn` 一致），防止 `https://localhost`、内网域名等绕过保留段判断。

## [v0.2.2] - 2026-05-04

### 新增
- `/asn` 接受 IP / 域名 / URL 输入，自动反查关联 ASN：
  - **IP 字面量** (IPv4/IPv6): 通过 RIPEstat `network-info` 端点拿到 ASN 后再走原有 `as-overview` + `whois` 流程。
  - **域名 / URL**: `urllib.parse` 提取 host (剥离 scheme / port / path / query / IPv6 ``[]`` 包裹)，异步 `loop.getaddrinfo` 解析为 IP 再查 ASN。
  - 输出新增 ``"(来自 <来源>)"`` 标注，例如 ``"AS13335 (来自 www.cloudflare.com → 104.16.123.96)"``。
- 域名解析后的 IP 会再次经过 `_reject_reserved_ip` 校验，避免 `https://localhost`、内网域名等绕过保留段判断造成无意义查询。

### 变更
- `cmd_asn` 拆分为 `_parse_asn_input` (纯字符串解析与校验) + `_resolve_host_to_asn` (DNS 与 network-info 网络查询) + 主流程调度三段，单函数职责更聚焦。
- `_format_asn_reply` 新增可选 `source` 参数用于标注 IP→ASN 反查链路。
- `/asn` 用法说明扩展为 ``"<AS号|IP|域名|URL>"`` 并附四条示例。

## [v0.2.1] - 2026-05-04

### 修复
- ASN 数据源从已下线的 `api.bgpview.io` 切换到 [RIPEstat](https://stat.ripe.net/) 的 `as-overview` + `whois` 两端点并发查询。`api.bgpview.io` 子域在公共 DNS 上返回 NXDOMAIN，导致 `/asn` 全部失败。
- 兼容不同 RIR 在 RIPEstat whois 端点上的字段命名差异（APNIC / RIPE / LACNIC 用小写 `as-name` / `descr` / `country`；ARIN 用 Pascal-case `OrgName` / `Country`），key 匹配大小写不敏感。
- ARIN 注册的 ASN 通过 overview 的 `holder` 字段（`"NAME - 组织描述"`）拆解 ` - ` 分隔符回填名称与描述，避免名称等于描述。

### 变更
- 内部常量按上游划分作用域：`_API_URL` / `_API_PARAMS` / `_API_TIMEOUT_SECONDS` → `_IP_API_URL` / `_IP_API_PARAMS` / `_HTTP_TIMEOUT_SECONDS`。
- ASN 32 位范围检查从 `_reject_reserved_asn` 抽出到 `cmd_asn` 入口校验，与保留 / 私有 / 文档段判断职责分层。
- `cmd_asn` 中 `asyncio.gather` 任一端点的故障会写入 `logger.warning`，即便另一端成功也不再静默吞掉。
- `_format_asn_reply` 守护链精简，使用 `str.removeprefix("Assigned by ")` 替代手动切片；新增 `_whois_first` 辅助函数封装嵌套 records 平铺逻辑。
- ASN 输出字段调整为：名称 / 描述 / 国家 / RIR / 是否公告 / 数据源；移除 bgpview 独有的 网站 / 流量估算 / 流量比例 / 分配日期（RIPEstat 不直接提供）。

## [v0.2.0] - 2026-05-04

### 新增
- `/asn <AS号>` 命令查询 ASN 归属与 RIR 信息，输入支持 `AS13335` / `as13335` / `13335` 三种形式。
- 私有 ASN（64512–65534, 4200000000–4294967294）与文档/保留段（0, 65535, 64496–64511, 65536–65551, 4294967295）的本地拒绝。

### 变更
- 插件重命名 `astrbot_plugin_ipquery` → `astrbot_plugin_netkit`（display_name "网络工具集 (NetKit)"）。
- 内部类 `IpQueryPlugin` → `NetKitPlugin`；回复前缀 `[IpQuery]` → `[NetKit]`。
- 仓库定位由 "IP 查询" 升级为 "网络工具集"，未来扩展 `ping` / `dns` / `whois` 等命令。

## [v0.1.0] - 2026-05-01

### 新增
- 首次发布 `astrbot_plugin_ipquery`，提供 `/ip <IPv4|IPv6|域名>` 命令，通过 [ip-api.com](https://ip-api.com/) 查询归属地、ISP、ASN、时区、经纬度等信息（中文输出）。
- 私有地址 / 回环 / 链路本地 / 组播等保留地址的本地拒绝，避免向上游发送无效请求。
