"""NetKit — AstrBot network toolbox plugin.

Registers:
- `/ip <IPv4|IPv6|域名>` — geolocation summary via ip-api.com
- `/asn <AS号|IP|域名|URL>` — ASN ownership / RIR info via stat.ripe.net
  (RIPEstat: `as-overview` + `whois` 端点；非 ASN 输入先经 `network-info`
  反查 ASN，域名走异步 getaddrinfo 解析为 IP)

后续可在此基础上扩展更多网络诊断/查询命令 (ping、dns、whois 等)。
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import struct
import urllib.parse
from typing import Any

import aiohttp

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star

# Shared HTTP client timeout (used by both ip-api and RIPEstat sessions).
_HTTP_TIMEOUT_SECONDS = 10

# ip-api.com — IP / 域名归属地
_IP_API_URL = "http://ip-api.com/json/{query}"
_IP_API_PARAMS = {"lang": "zh-CN"}
# ipwho.is — 用于多 IP 场景下"另解析的 IP"精简查询；官方声明免费无限、无需 key、走 HTTPS。
_IPWHOIS_URL = "https://ipwho.is/{ip}"
# 多 IP 输出 cap：CDN 域名可能解析出 100+ 个 IP，全部展示既无意义也浪费上游请求。
_MAX_EXTRA_IPS = 10
# Permissive sanity check: hostnames + IPv4/IPv6 literals fit within these chars.
# Reject anything else early to avoid sending junk to the upstream API.
_ALLOWED_TARGET_RE = re.compile(r"^[A-Za-z0-9_.\-:\[\]]+$")
_MAX_TARGET_LEN = 253

# RIPEstat — ASN 归属
_ASN_OVERVIEW_URL = "https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
_ASN_WHOIS_URL = "https://stat.ripe.net/data/whois/data.json?resource=AS{asn}"
_ASN_NETWORK_INFO_URL = "https://stat.ripe.net/data/network-info/data.json?resource={ip}"
_ASN_INPUT_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
_ASN_MAX = 4_294_967_295  # 32-bit ASN upper bound

# DoH (DNS-over-HTTPS) 多视角解析。地理 / 网络分散的解析器会因 EDNS Client
# Subnet 与 anycast 选址而看到权威给出的不同"最优节点"，聚合后能发现动态分配
# 域名（机场代理、Azure Front Door 等）真实使用的多个节点 IP。
# 此设计参考 amass / dnsdumpster 等子域枚举工具的 multi-resolver 思路。
#
# 每个端点标记其支持的协议：
#   "json" -> RFC 8427 风格（Google 首倡），URL 参数 + Accept: application/dns-json
#   "wire" -> RFC 8484 标准（仅 wire-format DNS message 二进制，更通用）
# 不少专业 DoH 端点（Quad9 / 360 / LibreDNS / Tiarap 等）只支持 wire；
# 想覆盖更多视角必须实现 wire-format 调用。
_DOH_ENDPOINTS: tuple[tuple[str, str, str], ...] = (
    ("Google",     "https://dns.google/resolve",                       "json"),
    ("AliDNS",     "https://dns.alidns.com/resolve",                   "json"),
    ("AdGuard",    "https://dns.adguard.com/resolve",                  "json"),
    ("DNS.SB",     "https://doh.dns.sb/dns-query",                     "json"),
    ("DNSPod",     "https://doh.pub/dns-query",                        "json"),
    ("NextDNS",    "https://dns.nextdns.io",                           "json"),
    ("360 (CN)",   "https://doh.360.cn/dns-query",                     "wire"),
    ("LibreDNS",   "https://doh.libredns.gr/dns-query",                "wire"),
    ("Tiarap",     "https://doh.tiar.app/dns-query",                   "wire"),
    # Quad9 强制 HTTP/2，aiohttp 默认 HTTP/1.1 不兼容；省略以避免无意义请求。
)
_DOH_PER_ENDPOINT_TIMEOUT = 3.0  # 单端点超时，慢的解析器不拖累其他

# EDNS Client Subnet (RFC 7871) 探测：部分权威 DNS 按 client subnet 给定制
# IP（机场代理、CDN GeoDNS 常见做法）。只查 DoH 服务器自己的出口视角会漏掉
# "大陆电信/联通/移动等用户实际看到的 IP"。我们在 Google JSON DoH 上注入若干
# 代表性 subnet 的 ECS 选项强制权威按那个网段分流，聚合到本地视角列表里。
# 选 /24 是因为权威 DNS 通常按 /24 粒度做 ECS 分组（更细的精度多数都被聚合）。
_ECS_VANTAGES: tuple[tuple[str, str], ...] = (
    ("CN-CT",  "61.139.2.0/24"),     # 四川电信骨干
    ("CN-CU",  "123.125.81.0/24"),   # 北京联通
    ("CN-CM",  "221.179.38.0/24"),   # 北京移动
    ("CN-EDU", "202.112.0.0/24"),    # 教育网 (清华)
    ("HK",     "203.80.96.0/24"),    # HK PCCW
    ("TW",     "168.95.1.0/24"),     # 中华电信
)
_ECS_DOH_URL = "https://dns.google/resolve"  # 已确认稳定支持 edns_client_subnet

# AlienVault OTX — passive DNS 历史。免费、无需 key，按 hostname 查询会返回该
# host 历史出现过的所有解析答案（含 first/last 时间戳）。dynamic / proxy 类
# 子域名通常 0 records；主域 / 高流量域名能拿到几百条。
_OTX_PDNS_URL = (
    "https://otx.alienvault.com/api/v1/indicators/hostname/{host}/passive_dns"
)
# OTX 接口对高流量域名（含数百条记录）响应慢，给它独立超时；普通调用 ~1-3 秒。
_OTX_TIMEOUT_SECONDS = 30
_IPHIST_MAX_ROWS = 20  # /iphist 最多展示行数，防止热门域名输出爆炸


class NetKitPlugin(Star):
    """NetKit — `/ip` (geolocation) + `/asn` (BGP ownership). 待扩展。"""

    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._session: aiohttp.ClientSession | None = None

    async def initialize(self) -> None:
        timeout = aiohttp.ClientTimeout(total=_HTTP_TIMEOUT_SECONDS)
        self._session = aiohttp.ClientSession(timeout=timeout)

    async def terminate(self) -> None:
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:
                logger.exception("[NetKit] failed to close aiohttp session")
            self._session = None

    @filter.command("ip")
    async def cmd_ip(self, event: AstrMessageEvent, target: str = ""):
        """查询 IP / 域名归属地。用法: /ip <IPv4|IPv6|域名|URL>"""
        raw = (target or "").strip()
        if not raw:
            yield event.plain_result(
                "用法: /ip <IPv4|IPv6|域名|URL>\n示例:\n"
                "  /ip 1.1.1.1\n"
                "  /ip 38.76.141.233:28367\n"
                "  /ip example.com\n"
                "  /ip https://www.cloudflare.com:443/foo"
            )
            return

        if len(raw) > _MAX_TARGET_LEN:
            yield event.plain_result("[NetKit] 输入无效: 超长。")
            return

        host = _extract_host(raw)
        if not host or not _ALLOWED_TARGET_RE.match(host):
            yield event.plain_result(
                "[NetKit] 输入无效: 仅支持 IPv4 / IPv6 / 域名 / URL。"
            )
            return

        reject_reason = _reject_reserved_ip(host)
        if reject_reason is not None:
            yield event.plain_result(f"[NetKit] 拒绝查询: {reject_reason}")
            return

        if self._session is None:
            yield event.plain_result("[NetKit] 插件未就绪，请稍后再试。")
            return

        try:
            ips = await asyncio.wait_for(
                _resolve_to_ips(host, self._session), timeout=_HTTP_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            yield event.plain_result(f"[NetKit] DNS 解析超时: {host}")
            return
        if not ips:
            yield event.plain_result(f"[NetKit] 无法解析 {host}")
            return

        # SSRF / 无意义查询防护：解析后的每一个 IP 再次校验保留段。
        for ip in ips:
            rej = _reject_reserved_ip(ip)
            if rej is not None:
                yield event.plain_result(
                    f"[NetKit] 拒绝查询: {host} 解析到 {ip}（{rej}）"
                )
                return

        # 首个 IP 走 ip-api 拿全字段中文详细信息。
        primary_ip = ips[0]
        try:
            primary_text = await _query_ip_api_detail(self._session, host, primary_ip)
        except asyncio.TimeoutError:
            yield event.plain_result("[NetKit] 查询超时，请稍后再试。")
            return
        except aiohttp.ClientError as exc:
            logger.warning("[NetKit] ip-api error for %s: %s", primary_ip, exc)
            yield event.plain_result(f"[NetKit] 网络错误: {exc}")
            return
        except ValueError as exc:
            logger.warning("[NetKit] ip-api invalid JSON for %s: %s", primary_ip, exc)
            yield event.plain_result("[NetKit] 上游返回数据无法解析。")
            return
        if primary_text is None:
            yield event.plain_result(
                f"[NetKit] 上游接口异常或查询失败: {primary_ip}"
            )
            return

        # 多 IP 场景：剩余 IP 用 ipwho.is 拿精简一行（无配额限制）。
        extras = ips[1 : 1 + _MAX_EXTRA_IPS]
        truncated = len(ips) - 1 - len(extras)
        if extras:
            extra_lines = await _format_extra_ips(self._session, extras)
            header = f"— 另解析到 {len(ips) - 1} 个 IP"
            if truncated > 0:
                header += f"（仅显示前 {len(extras)} 个）"
            header += "（数据源 ipwho.is）—"
            primary_text = f"{primary_text}\n\n{header}\n{extra_lines}"

        yield event.plain_result(primary_text)

    @filter.command("asn")
    async def cmd_asn(self, event: AstrMessageEvent, target: str = ""):
        """查询 ASN 归属信息。用法: /asn <AS号|IP|域名|URL>"""
        raw = (target or "").strip()
        if not raw:
            yield event.plain_result(
                "用法: /asn <AS号|IP|域名|URL>\n示例:\n"
                "  /asn AS13335\n"
                "  /asn 47.238.146.96\n"
                "  /asn https://1.1.1.1\n"
                "  /asn https://api.bgpview.io:443"
            )
            return

        asn_number, host, parse_error = _parse_asn_input(raw)
        if parse_error is not None:
            yield event.plain_result(parse_error)
            return

        if self._session is None:
            yield event.plain_result("[NetKit] 插件未就绪，请稍后再试。")
            return

        source_note: str | None = None
        if host is not None:
            asn_number, source_note, lookup_error = await _resolve_host_to_asn(
                self._session, host
            )
            if lookup_error is not None:
                yield event.plain_result(lookup_error)
                return

        assert asn_number is not None  # guaranteed by the branches above
        urls = (
            _ASN_OVERVIEW_URL.format(asn=asn_number),
            _ASN_WHOIS_URL.format(asn=asn_number),
        )
        results = await asyncio.gather(
            *(_fetch_ripe_data(self._session, u) for u in urls),
            return_exceptions=True,
        )
        overview = results[0] if isinstance(results[0], dict) else None
        whois = results[1] if isinstance(results[1], dict) else None

        # 即使一端拿到数据也记录另一端的故障 — 否则 production 故障会被吞。
        for url, r in zip(urls, results):
            if isinstance(r, BaseException):
                logger.warning(
                    "[NetKit] ASN partial fetch failed url=%s err=%r", url, r
                )

        if overview is None and whois is None:
            excs = [r for r in results if isinstance(r, BaseException)]
            if any(isinstance(e, asyncio.TimeoutError) for e in excs):
                yield event.plain_result("[NetKit] 查询超时，请稍后再试。")
                return
            net_excs = [e for e in excs if isinstance(e, aiohttp.ClientError)]
            if net_excs:
                yield event.plain_result(f"[NetKit] 网络错误: {net_excs[0]}")
                return
            if excs:
                yield event.plain_result("[NetKit] 上游返回数据无法解析。")
                return
            yield event.plain_result(
                f"[NetKit] 未找到 AS{asn_number} 的信息（可能未分配）。"
            )
            return

        yield event.plain_result(
            _format_asn_reply(asn_number, overview, whois, source_note)
        )

    @filter.command("iphist")
    async def cmd_iphist(self, event: AstrMessageEvent, target: str = ""):
        """查询域名/主机的 passive DNS 历史 IP。用法: /iphist <域名|URL>"""
        raw = (target or "").strip()
        if not raw:
            yield event.plain_result(
                "用法: /iphist <域名|URL>\n示例:\n"
                "  /iphist www.cloudflare.com\n"
                "  /iphist https://api.example.com:443\n"
                "数据来自 AlienVault OTX 的 passive DNS 索引；"
                "动态/短期域名通常无历史记录。"
            )
            return

        if len(raw) > _MAX_TARGET_LEN:
            yield event.plain_result("[NetKit] 输入无效: 超长。")
            return

        host = _extract_host(raw)
        if not host or not _ALLOWED_TARGET_RE.match(host):
            yield event.plain_result(
                "[NetKit] 输入无效: 仅支持域名 / URL。"
            )
            return

        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            yield event.plain_result(
                "[NetKit] 输入是 IP 字面量，passive DNS 仅对域名有意义。"
            )
            return

        if self._session is None:
            yield event.plain_result("[NetKit] 插件未就绪，请稍后再试。")
            return

        try:
            records = await asyncio.wait_for(
                _query_otx_passive_dns(self._session, host),
                timeout=_OTX_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            yield event.plain_result(
                f"[NetKit] OTX 查询超时（>{_OTX_TIMEOUT_SECONDS}s）；"
                "热门域名记录数过多时常见，可稍后重试或换更具体的子域查询。"
            )
            return
        except aiohttp.ClientError as exc:
            logger.warning("[NetKit] OTX error for %s: %s", host, exc)
            yield event.plain_result(f"[NetKit] 网络错误: {exc}")
            return
        except ValueError as exc:
            logger.warning("[NetKit] OTX invalid JSON for %s: %s", host, exc)
            yield event.plain_result("[NetKit] 上游返回数据无法解析。")
            return

        if not records:
            yield event.plain_result(
                f"[NetKit] {host} 在 AlienVault OTX 中无 A/AAAA passive DNS 记录"
                f"（动态分配 / 短期域名常见此结果）。"
            )
            return

        yield event.plain_result(_format_iphist_reply(host, records))


def _reject_reserved_ip(target: str) -> str | None:
    """Return a Chinese reason if the target is a reserved IP literal, else None.

    Domains are passed through (we cannot resolve them locally without DNS).
    """
    if target.lower() in {"localhost", "ip6-localhost", "ip6-loopback"}:
        return "回环主机名不在查询范围。"
    candidate = target
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return None  # not an IP literal — let the API resolve it

    if ip.is_loopback:
        return "回环地址 (loopback) 不在查询范围。"
    if ip.is_private:
        return "私有地址 (RFC1918 / ULA) 不在查询范围。"
    if ip.is_link_local:
        return "链路本地地址不在查询范围。"
    if ip.is_multicast:
        return "组播地址不在查询范围。"
    if ip.is_unspecified:
        return "未指定地址 (0.0.0.0 / ::) 无法查询。"
    if ip.is_reserved:
        return "保留地址不在查询范围。"
    return None


def _format_reply(target: str, data: dict[str, Any]) -> str:
    """Render the API JSON as a Chinese plain-text summary."""

    def pick(key: str) -> str:
        value = data.get(key)
        if value is None or value == "":
            return "-"
        return str(value)

    resolved_ip = pick("query")
    country = pick("country")
    region = pick("regionName")
    city = pick("city")
    location = " ".join(part for part in (country, region, city) if part and part != "-") or "-"

    lat = data.get("lat")
    lon = data.get("lon")
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        coords = f"{lat}, {lon}"
    else:
        coords = "-"

    lines = [
        f"查询地址: {target}",
        f"IP: {resolved_ip}",
        f"国家: {country}",
        f"地区: {region}",
        f"城市: {city}",
        f"归属: {location}",
        f"运营商/ISP: {pick('isp')}",
        f"组织: {pick('org')}",
        f"ASN: {pick('as')}",
        f"时区: {pick('timezone')}",
        f"经纬度: {coords}",
    ]
    return "\n".join(lines)


def _reject_reserved_asn(asn: int) -> str | None:
    """Return a Chinese reason if the ASN is reserved/private/documentation.

    调用方需先确保 ``0 <= asn <= 4294967295``；此函数只判断该范围内的特殊段。
    """
    if asn == 0 or asn == 65535 or asn == _ASN_MAX:
        return "保留 ASN 不在查询范围。"
    if 64512 <= asn <= 65534:
        return "16 位私有 ASN (64512–65534) 不在查询范围。"
    if 4_200_000_000 <= asn <= 4_294_967_294:
        return "32 位私有 ASN (4200000000–4294967294) 不在查询范围。"
    if 64496 <= asn <= 64511 or 65536 <= asn <= 65551:
        return "文档/示例用 ASN 不在查询范围。"
    return None


def _whois_first(whois: dict[str, Any] | None, *keys: str) -> str:
    """Return the first non-empty value for any of ``keys`` in a whois payload.

    Whois 端点返回的 ``records`` 是 ``List[List[Dict]]`` 嵌套数组；不同 RIR 用
    不同 key (APNIC: ``as-name``/``descr``/``country``；ARIN: ``OrgName``/``Country``)，
    因此匹配采用大小写不敏感。命中第一个非空值后立即返回。
    """
    if not isinstance(whois, dict) or not keys:
        return "-"
    targets = {k.lower() for k in keys}
    for record in whois.get("records") or []:
        for item in record or []:
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            if not isinstance(key, str) or key.lower() not in targets:
                continue
            value = item.get("value")
            if value:
                return str(value)
    return "-"


def _format_asn_reply(
    asn: int,
    overview: dict[str, Any] | None,
    whois: dict[str, Any] | None,
    source: str | None = None,
) -> str:
    """Render RIPEstat payloads (whois 优先 + overview 补全) -> Chinese summary.

    ``source`` 用于标注 IP/域名反查的来源（例如 ``"47.238.146.96"`` 或
    ``"api.bgpview.io → 1.2.3.4"``）；ASN 直接查询时为 None。
    """
    # APNIC/RIPE/LACNIC 风格的 whois 才有 as-name/descr；ARIN 注册的 ASN 这两项缺失，
    # 改由 overview.holder ("CLOUDFLARENET - Cloudflare, Inc.") 拆解后补全。
    name = _whois_first(whois, "as-name")
    description = _whois_first(whois, "descr")
    country = _whois_first(whois, "country", "Country")
    rir = "-"
    announced = "-"

    if isinstance(overview, dict):
        holder = overview.get("holder")
        if isinstance(holder, str) and holder.strip():
            # ARIN 风格: "GOOGLE - Google LLC"; APNIC 风格: "ALIBABA-CN-NET Alibaba ..."
            if " - " in holder:
                head, _, tail = holder.partition(" - ")
            else:
                head, _, tail = holder.partition(" ")
            if name == "-":
                name = head or holder
            if description == "-" and tail.strip():
                description = tail.strip()
        block_desc = (overview.get("block") or {}).get("desc")
        if isinstance(block_desc, str) and block_desc:
            rir = block_desc.removeprefix("Assigned by ").strip() or block_desc
        if "announced" in overview:
            announced = "是" if overview["announced"] else "否"

    header = f"查询 ASN: AS{asn}"
    if source:
        header += f" (来自 {source})"
    return "\n".join([
        header,
        f"名称: {name}",
        f"描述: {description}",
        f"国家: {country}",
        f"RIR: {rir}",
        f"是否公告: {announced}",
        "数据源: RIPEstat",
    ])


def _extract_host(raw: str) -> str:
    """Extract a host (IP literal or domain) from URL / host:port / bare forms.

    覆盖以下输入：

    - 直接 IP 字面量：``"1.1.1.1"`` / ``"[::1]"`` / ``"2001:db8::1"``
    - host[:port]：``"api.bgpview.io:443"`` / ``"[::1]:8080"``
    - 完整 URL：``"https://example.com/foo?x=1"`` / ``"https://[::1]:8080/p"``

    返回剥离 scheme / port / path / query / IPv6 ``[]`` 后的 host。
    """
    s = raw.strip().strip('"\'')
    if not s:
        return s
    # 直接 IP 字面量优先（含 [::1] 包裹），避免裸 IPv6 被 urlsplit 当成 host:port。
    candidate = s[1:-1] if s.startswith("[") and s.endswith("]") else s
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    # 否则按 URL 处理：用 // 让 urlsplit 把 host[:port] 当作 netloc 解析。
    target = s if "://" in s else "//" + s
    try:
        host = urllib.parse.urlsplit(target).hostname
    except ValueError:
        return s
    return host or s


def _parse_asn_input(raw: str) -> tuple[int | None, str | None, str | None]:
    """Classify the raw input and surface validation errors.

    Returns ``(asn_number, host, error_text)``：

    - ASN 数字输入：``(asn_number, None, None)``
    - IP/域名/URL 输入：``(None, host, None)``
    - 输入非法或落入保留段：``(None, None, error_text)``

    主流程不必关心两路分支的内部判断顺序，只看返回值。
    """
    asn_match = _ASN_INPUT_RE.match(raw)
    if asn_match:
        asn = int(asn_match.group(1))
        if asn > _ASN_MAX:
            return None, None, "[NetKit] 输入无效: ASN 超出 32 位范围 (0–4294967295)。"
        reject = _reject_reserved_asn(asn)
        if reject is not None:
            return None, None, f"[NetKit] 拒绝查询: {reject}"
        return asn, None, None

    host = _extract_host(raw)
    if (
        not host
        or len(host) > _MAX_TARGET_LEN
        or not _ALLOWED_TARGET_RE.match(host)
    ):
        return (
            None,
            None,
            "[NetKit] 输入无效: 期望 ASN 编号、IP 或域名/URL。",
        )
    reject = _reject_reserved_ip(host)
    if reject is not None:
        return None, None, f"[NetKit] 拒绝查询: {reject}"
    return None, host, None


def _build_dns_query(host: str, rrtype: int) -> bytes:
    """Build a minimal DNS wire-format query for ``host`` ``rrtype``.

    Per RFC 8484, DoH transactions use ID=0 (responses must echo it; using 0
    avoids leaking randomness across cache layers). Flags 0x0100 = standard
    query with RD (recursion desired) set.
    """
    header = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 0)
    parts = host.rstrip(".").split(".")
    qname = b"".join(
        bytes([len(p.encode("idna"))]) + p.encode("idna") for p in parts if p
    ) + b"\x00"
    return header + qname + struct.pack("!HH", rrtype, 1)


def _skip_dns_name(data: bytes, pos: int) -> int:
    """Skip a DNS name starting at ``pos``. Returns the next byte offset, or
    -1 if the encoding is malformed.
    """
    n = len(data)
    while pos < n:
        ln = data[pos]
        if ln == 0:
            return pos + 1
        if (ln & 0xC0) == 0xC0:
            return pos + 2  # compression pointer (2 bytes total)
        if ln & 0xC0:
            return -1  # reserved label-type bits set
        pos += 1 + ln
        if pos > n:
            return -1
    return -1


def _parse_dns_answer(data: bytes, rrtype: int) -> list[str]:
    """Extract IP strings of ``rrtype`` (1=A, 28=AAAA) from a wire-format
    DNS response packet. Malformed bytes degrade to an empty list.
    """
    if len(data) < 12:
        return []
    ancount = struct.unpack_from("!H", data, 6)[0]
    if ancount == 0:
        return []
    pos = _skip_dns_name(data, 12)
    if pos < 0 or pos + 4 > len(data):
        return []
    pos += 4  # qtype + qclass

    ips: list[str] = []
    for _ in range(ancount):
        pos = _skip_dns_name(data, pos)
        if pos < 0 or pos + 10 > len(data):
            break
        rtype, rclass, _ttl, rdlen = struct.unpack_from("!HHIH", data, pos)
        pos += 10
        if pos + rdlen > len(data):
            break
        rdata = data[pos : pos + rdlen]
        pos += rdlen
        if rtype != rrtype or rclass != 1:
            continue
        try:
            if rtype == 1 and rdlen == 4:
                ips.append(str(ipaddress.IPv4Address(rdata)))
            elif rtype == 28 and rdlen == 16:
                ips.append(str(ipaddress.IPv6Address(rdata)))
        except (ipaddress.AddressValueError, ValueError):
            continue
    return ips


async def _query_doh(
    session: aiohttp.ClientSession,
    name: str,
    url: str,
    mode: str,
    host: str,
    rrtype: int,
    ecs: str | None = None,
) -> list[str]:
    """Query a single DoH endpoint for ``host`` ``rrtype``.

    ``mode`` selects between ``"json"`` (RFC 8427-style, Google/Cloudflare
    JSON DoH) and ``"wire"`` (RFC 8484, application/dns-message). Per-endpoint
    timeout is enforced by the caller via ``asyncio.wait_for``.

    ``ecs`` (CIDR like ``"61.139.2.0/24"``) attaches an EDNS Client Subnet
    hint via the ``edns_client_subnet`` parameter. Only takes effect on JSON
    DoH; wire-mode currently ignores it (would need an OPT record).

    Returns a list of IP strings, or an empty list on any failure.
    """
    try:
        if mode == "json":
            params = {"name": host, "type": str(rrtype)}
            if ecs:
                params["edns_client_subnet"] = ecs
            async with session.get(
                url,
                params=params,
                headers={"Accept": "application/dns-json"},
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
            answers = data.get("Answer") if isinstance(data, dict) else None
            if not isinstance(answers, list):
                return []
            ips: list[str] = []
            for item in answers:
                if isinstance(item, dict) and item.get("type") == rrtype:
                    value = item.get("data")
                    if isinstance(value, str) and value:
                        ips.append(value)
            return ips

        # mode == "wire": RFC 8484 binary
        body = _build_dns_query(host, rrtype)
        async with session.post(
            url,
            data=body,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
        ) as resp:
            if resp.status != 200:
                return []
            packet = await resp.read()
        return _parse_dns_answer(packet, rrtype)
    except (asyncio.TimeoutError, aiohttp.ClientError, ValueError) as exc:
        logger.debug("[NetKit] DoH %s (%s) failed for %s: %r", name, mode, host, exc)
        return []


async def _resolve_via_doh(
    session: aiohttp.ClientSession, host: str
) -> list[str]:
    """Concurrently query every configured DoH endpoint plus the ECS vantage
    set on Google JSON DoH, both for A and AAAA. Returns the merged IP list.

    Each task is independently capped at ``_DOH_PER_ENDPOINT_TIMEOUT``.
    """
    tasks: list[asyncio.Future[list[str]]] = []

    # Per-endpoint, no ECS — captures each resolver's own vantage point.
    for name, url, mode in _DOH_ENDPOINTS:
        for rrtype in (1, 28):
            tasks.append(
                asyncio.wait_for(
                    _query_doh(session, name, url, mode, host, rrtype),
                    timeout=_DOH_PER_ENDPOINT_TIMEOUT,
                )
            )

    # ECS-injected vantages on Google JSON DoH — covers carrier / region
    # specific GeoDNS responses we'd otherwise miss.
    for label, subnet in _ECS_VANTAGES:
        for rrtype in (1, 28):
            tasks.append(
                asyncio.wait_for(
                    _query_doh(
                        session, f"ECS-{label}", _ECS_DOH_URL,
                        "json", host, rrtype, ecs=subnet,
                    ),
                    timeout=_DOH_PER_ENDPOINT_TIMEOUT,
                )
            )

    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[str] = []
    for r in results:
        if isinstance(r, list):
            out.extend(r)
    return out


async def _resolve_to_ips(
    host: str, session: aiohttp.ClientSession | None = None
) -> list[str]:
    """Resolve ``host`` to all unique IPs we can discover.

    Strategy:
      1. IP literal -> single-element list (no network).
      2. ``loop.getaddrinfo`` for the local-resolver answer.
      3. If a session is provided, multi-DoH aggregation runs in parallel
         and merges with the system answer.

    The DoH layer is what catches dynamic / round-robin domains where the
    authoritative server returns a different "nearest" node per vantage
    point (Azure Front Door, 机场代理, etc.).
    """
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass

    seen: set[str] = set()
    ordered: list[str] = []

    def _add_many(ips: list[str]) -> None:
        for ip in ips:
            if not ip or ip in seen:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            seen.add(ip)
            ordered.append(ip)

    # 1) 系统解析器视角（受本机 DNS 服务器影响）
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
    except OSError:
        infos = []
    _add_many([info[4][0] for info in infos if info[4]])

    # 2) DoH 多视角并发（前提：调用方传了 session）
    if session is not None:
        _add_many(await _resolve_via_doh(session, host))

    return ordered


async def _resolve_to_ip(
    host: str, session: aiohttp.ClientSession | None = None
) -> str | None:
    """Resolve ``host`` to its first IP. IP literals pass through.

    Used by ``/asn`` reverse lookup where one IP is enough.
    """
    ips = await _resolve_to_ips(host, session)
    return ips[0] if ips else None


async def _query_ip_api_detail(
    session: aiohttp.ClientSession, label: str, ip: str
) -> str | None:
    """Query ip-api for ``ip`` and render the Chinese summary keyed on ``label``.

    Returns formatted text on success, or None when the upstream returned a
    non-200 / status != "success" payload. Transport / parse errors propagate.
    """
    async with session.get(
        _IP_API_URL.format(query=ip), params=_IP_API_PARAMS
    ) as resp:
        if resp.status != 200:
            return None
        data: dict[str, Any] = await resp.json(content_type=None)
    if data.get("status") != "success":
        return None
    return _format_reply(label, data)


async def _query_ipwhois(
    session: aiohttp.ClientSession, ip: str
) -> dict[str, Any] | None:
    """Single-IP query against ipwho.is. Returns the JSON dict or None."""
    async with session.get(_IPWHOIS_URL.format(ip=ip)) as resp:
        if resp.status != 200:
            return None
        return await resp.json(content_type=None)


async def _format_extra_ips(
    session: aiohttp.ClientSession, ips: list[str]
) -> str:
    """Concurrently fetch ipwho.is summaries for ``ips`` and render one per line.

    Per-IP failures degrade to ``"<ip> — 查询失败"`` rather than aborting the
    whole list.
    """
    results = await asyncio.gather(
        *(_query_ipwhois(session, ip) for ip in ips),
        return_exceptions=True,
    )
    lines: list[str] = []
    for ip, r in zip(ips, results):
        if isinstance(r, BaseException):
            logger.warning("[NetKit] ipwho.is failed for %s: %r", ip, r)
            lines.append(f"{ip} — 查询失败")
            continue
        if not isinstance(r, dict) or not r.get("success", True) or "ip" not in r:
            lines.append(f"{ip} — 查询失败")
            continue
        isp = (r.get("connection") or {}).get("isp") or r.get("isp") or "-"
        parts = [r.get("country"), r.get("region"), r.get("city")]
        location = ", ".join(p for p in parts if p) or "-"
        lines.append(f"{ip} — {isp} ({location})")
    return "\n".join(lines)


async def _query_otx_passive_dns(
    session: aiohttp.ClientSession, host: str
) -> list[dict[str, Any]]:
    """Fetch passive-DNS records for ``host`` from AlienVault OTX.

    Returns the records filtered to A/AAAA on the exact hostname, sorted by
    ``last`` descending (most recent first). OTX returns subdomain records
    too; this helper drops them since /iphist is host-specific.

    Bypasses the plugin-wide 10 s session timeout because OTX responses for
    high-traffic domains routinely take 10–25 s; outer caller still bounds
    the wait.
    """
    url = _OTX_PDNS_URL.format(host=urllib.parse.quote(host, safe=""))
    request_timeout = aiohttp.ClientTimeout(total=_OTX_TIMEOUT_SECONDS)
    async with session.get(url, timeout=request_timeout) as resp:
        if resp.status != 200:
            return []
        data = await resp.json(content_type=None)
    rows = data.get("passive_dns") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []
    target = host.lower()
    filtered: list[dict[str, Any]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        if (r.get("hostname") or "").lower() != target:
            continue
        if r.get("record_type") not in ("A", "AAAA"):
            continue
        if not r.get("address"):
            continue
        filtered.append(r)
    filtered.sort(key=lambda r: r.get("last") or "", reverse=True)
    return filtered


def _format_iphist_reply(host: str, records: list[dict[str, Any]]) -> str:
    """Render OTX passive-DNS records as a multi-line summary."""
    shown = records[:_IPHIST_MAX_ROWS]
    truncated = len(records) - len(shown)
    lines = [
        f"DNS 历史 — {host}",
        "数据源: AlienVault OTX (passive DNS)",
        f"共 {len(records)} 条 A/AAAA 记录" + (
            f"，仅显示最近 {len(shown)} 条" if truncated > 0 else ""
        ),
        "",
    ]
    for r in shown:
        addr = r.get("address") or "-"
        first = (r.get("first") or "")[:10] or "-"
        last = (r.get("last") or "")[:10] or "-"
        country = r.get("flag_title") or "-"
        asn = r.get("asn") or "-"
        lines.append(
            f"  {addr}\n"
            f"    {country} | {asn}\n"
            f"    首见 {first}, 最近 {last}"
        )
    if truncated > 0:
        lines.append(f"\n... 另有 {truncated} 条更早记录未显示")
    return "\n".join(lines)


async def _lookup_asn_for_ip(
    session: aiohttp.ClientSession, ip: str
) -> int | None:
    """Return the first announced ASN for ``ip`` via RIPEstat ``network-info``."""
    data = await _fetch_ripe_data(
        session, _ASN_NETWORK_INFO_URL.format(ip=ip)
    )
    if not isinstance(data, dict):
        return None
    asns = data.get("asns")
    if not isinstance(asns, list):
        return None
    for entry in asns:
        try:
            return int(entry)
        except (TypeError, ValueError):
            continue
    return None


async def _resolve_host_to_asn(
    session: aiohttp.ClientSession, host: str
) -> tuple[int | None, str | None, str | None]:
    """Resolve ``host`` to an IP, then look up its announced ASN.

    Returns ``(asn_number, source_note, error_text)``. On success exactly one of
    ``asn_number`` and ``error_text`` is set; ``source_note`` describes the
    lookup chain for display, e.g. ``"api.bgpview.io → 1.2.3.4"`` or just
    ``"47.238.146.96"`` when the input was already an IP.
    """
    try:
        ip = await asyncio.wait_for(
            _resolve_to_ip(host, session), timeout=_HTTP_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        return None, None, f"[NetKit] DNS 解析超时: {host}"
    if ip is None:
        return None, None, f"[NetKit] 无法解析 {host}"

    # SSRF / 无意义查询防护：解析后的 IP 再次走保留段判断。
    reject = _reject_reserved_ip(ip)
    if reject is not None:
        return (
            None,
            None,
            f"[NetKit] 拒绝查询: {host} 解析到 {ip}（{reject}）",
        )

    try:
        asn = await _lookup_asn_for_ip(session, ip)
    except asyncio.TimeoutError:
        return None, None, "[NetKit] 查询超时，请稍后再试。"
    except aiohttp.ClientError as exc:
        logger.warning("[NetKit] network-info error for %s: %s", ip, exc)
        return None, None, f"[NetKit] 网络错误: {exc}"
    except ValueError:
        return None, None, "[NetKit] 上游返回数据无法解析。"
    if asn is None:
        return (
            None,
            None,
            f"[NetKit] 未能从 {host} ({ip}) 查到关联的 ASN（可能未公告或未分配）。",
        )

    source_note = host if host == ip else f"{host} → {ip}"
    return asn, source_note, None


async def _fetch_ripe_data(
    session: aiohttp.ClientSession, url: str
) -> dict[str, Any] | None:
    """Call a RIPEstat data endpoint and return the `data` object on success.

    Returns None when the upstream signals an unsupported / empty resource;
    raises asyncio.TimeoutError / aiohttp.ClientError / ValueError on transport
    or parse failures so the caller can surface a specific error.
    """
    async with session.get(url) as resp:
        if resp.status != 200:
            return None
        payload = await resp.json(content_type=None)
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return None
    data = payload.get("data")
    return data if isinstance(data, dict) and data else None
