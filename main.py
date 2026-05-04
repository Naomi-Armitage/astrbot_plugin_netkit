"""NetKit — AstrBot network toolbox plugin.

Registers:
- `/ip <IPv4|IPv6|域名>` — geolocation summary via ip-api.com
- `/asn <AS号>` — ASN ownership / RIR info via stat.ripe.net (RIPEstat:
  `as-overview` + `whois` 端点合并)

后续可在此基础上扩展更多网络诊断/查询命令 (ping、dns、whois 等)。
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
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
# Permissive sanity check: hostnames + IPv4/IPv6 literals fit within these chars.
# Reject anything else early to avoid sending junk to the upstream API.
_ALLOWED_TARGET_RE = re.compile(r"^[A-Za-z0-9_.\-:\[\]]+$")
_MAX_TARGET_LEN = 253

# RIPEstat — ASN 归属
_ASN_OVERVIEW_URL = "https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
_ASN_WHOIS_URL = "https://stat.ripe.net/data/whois/data.json?resource=AS{asn}"
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
        """查询 IP / 域名归属地。用法: /ip <IPv4|IPv6|域名>"""
        target = (target or "").strip()
        if not target:
            yield event.plain_result(
                "用法: /ip <IPv4|IPv6|域名>\n示例:\n  /ip 1.1.1.1\n  /ip example.com"
            )
            return

        if len(target) > _MAX_TARGET_LEN or not _ALLOWED_TARGET_RE.match(target):
            yield event.plain_result(
                "[NetKit] 输入无效: 仅支持 IPv4 / IPv6 / 域名。"
            )
            return

        reject_reason = _reject_reserved_ip(target)
        if reject_reason is not None:
            yield event.plain_result(f"[NetKit] 拒绝查询: {reject_reason}")
            return

        if self._session is None:
            yield event.plain_result("[NetKit] 插件未就绪，请稍后再试。")
            return

        # ip-api.com path segment expects bare IPv6 (no [] wrapper).
        query = target[1:-1] if target.startswith("[") and target.endswith("]") else target
        try:
            async with self._session.get(
                _IP_API_URL.format(query=query), params=_IP_API_PARAMS
            ) as resp:
                if resp.status != 200:
                    yield event.plain_result(
                        f"[NetKit] 上游接口异常: HTTP {resp.status}"
                    )
                    return
                data: dict[str, Any] = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            yield event.plain_result("[NetKit] 查询超时，请稍后再试。")
            return
        except aiohttp.ClientError as exc:
            logger.warning("[NetKit] network error for %r: %s", target, exc)
            yield event.plain_result(f"[NetKit] 网络错误: {exc}")
            return
        except ValueError as exc:
            logger.warning("[NetKit] invalid JSON for %r: %s", target, exc)
            yield event.plain_result("[NetKit] 上游返回数据无法解析。")
            return

        if data.get("status") != "success":
            reason = data.get("message") or "未知错误"
            yield event.plain_result(f"[NetKit] 查询失败: {reason}")
            return

        yield event.plain_result(_format_reply(target, data))

    @filter.command("asn")
    async def cmd_asn(self, event: AstrMessageEvent, target: str = ""):
        """查询 ASN 归属信息。用法: /asn <AS号>，例如 /asn AS13335 或 /asn 13335"""
        raw = (target or "").strip()
        if not raw:
            yield event.plain_result(
                "用法: /asn <AS号>\n示例:\n  /asn AS13335\n  /asn 45102"
            )
            return

        match = _ASN_INPUT_RE.match(raw)
        if match is None:
            yield event.plain_result(
                "[NetKit] 输入无效: 仅支持纯数字或带 AS 前缀的 ASN，例如 AS13335。"
            )
            return

        asn_number = int(match.group(1))
        # 输入合法性 (范围) 在前；保留段判断在后 — 两类拒绝语义独立。
        if asn_number > _ASN_MAX:
            yield event.plain_result(
                "[NetKit] 输入无效: ASN 超出 32 位范围 (0–4294967295)。"
            )
            return
        reject_reason = _reject_reserved_asn(asn_number)
        if reject_reason is not None:
            yield event.plain_result(f"[NetKit] 拒绝查询: {reject_reason}")
            return

        if self._session is None:
            yield event.plain_result("[NetKit] 插件未就绪，请稍后再试。")
            return

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

        yield event.plain_result(_format_asn_reply(asn_number, overview, whois))


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
) -> str:
    """Render RIPEstat payloads (whois 优先 + overview 补全) -> Chinese summary."""
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

    return "\n".join([
        f"查询 ASN: AS{asn}",
        f"名称: {name}",
        f"描述: {description}",
        f"国家: {country}",
        f"RIR: {rir}",
        f"是否公告: {announced}",
        "数据源: RIPEstat",
    ])


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
