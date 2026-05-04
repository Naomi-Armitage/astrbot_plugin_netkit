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
                _resolve_to_ips(host), timeout=_HTTP_TIMEOUT_SECONDS
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


async def _resolve_to_ips(host: str) -> list[str]:
    """Async DNS resolve ``host`` to all unique IPs (in order). IP literals
    pass through as a single-element list.

    Used by ``cmd_ip`` (展示所有解析结果) and ``_resolve_to_ip`` (反查 ASN
    时只需第一个)。
    """
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
    except OSError:
        return []
    seen: set[str] = set()
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if ip and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


async def _resolve_to_ip(host: str) -> str | None:
    """Async DNS resolve ``host`` to its first IP. IP literals pass through."""
    ips = await _resolve_to_ips(host)
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
            _resolve_to_ip(host), timeout=_HTTP_TIMEOUT_SECONDS
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
