"""NetKit — AstrBot network toolbox plugin.

Registers:
- `/ip <IPv4|IPv6|域名>` — geolocation summary via ip-api.com
- `/asn <AS号>` — ASN ownership / RIR info via bgpview.io

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

_API_URL = "http://ip-api.com/json/{query}"
_API_PARAMS = {"lang": "zh-CN"}
_API_TIMEOUT_SECONDS = 10
# Permissive sanity check: hostnames + IPv4/IPv6 literals fit within these chars.
# Reject anything else early to avoid sending junk to the upstream API.
_ALLOWED_TARGET_RE = re.compile(r"^[A-Za-z0-9_.\-:\[\]]+$")
_MAX_TARGET_LEN = 253

_ASN_API_URL = "https://api.bgpview.io/asn/{asn}"
_ASN_INPUT_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
_ASN_MAX = 4_294_967_295  # 32-bit ASN upper bound


class NetKitPlugin(Star):
    """NetKit — `/ip` (geolocation) + `/asn` (BGP ownership). 待扩展。"""

    def __init__(self, context: Context) -> None:
        super().__init__(context)
        self._session: aiohttp.ClientSession | None = None

    async def initialize(self) -> None:
        timeout = aiohttp.ClientTimeout(total=_API_TIMEOUT_SECONDS)
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
                _API_URL.format(query=query), params=_API_PARAMS
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
        reject_reason = _reject_reserved_asn(asn_number)
        if reject_reason is not None:
            yield event.plain_result(f"[NetKit] 拒绝查询: {reject_reason}")
            return

        if self._session is None:
            yield event.plain_result("[NetKit] 插件未就绪，请稍后再试。")
            return

        try:
            async with self._session.get(_ASN_API_URL.format(asn=asn_number)) as resp:
                if resp.status != 200:
                    yield event.plain_result(
                        f"[NetKit] 上游接口异常: HTTP {resp.status}"
                    )
                    return
                payload: dict[str, Any] = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            yield event.plain_result("[NetKit] 查询超时，请稍后再试。")
            return
        except aiohttp.ClientError as exc:
            logger.warning("[NetKit] ASN network error for AS%s: %s", asn_number, exc)
            yield event.plain_result(f"[NetKit] 网络错误: {exc}")
            return
        except ValueError as exc:
            logger.warning("[NetKit] ASN invalid JSON for AS%s: %s", asn_number, exc)
            yield event.plain_result("[NetKit] 上游返回数据无法解析。")
            return

        if payload.get("status") != "ok":
            reason = payload.get("status_message") or "未知错误"
            yield event.plain_result(f"[NetKit] 查询失败: {reason}")
            return

        data = payload.get("data") or {}
        if not data:
            yield event.plain_result(
                f"[NetKit] 未找到 AS{asn_number} 的信息（可能未分配）。"
            )
            return

        yield event.plain_result(_format_asn_reply(asn_number, data))


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
    """Return a Chinese reason if the ASN is reserved/private, else None."""
    if asn == 0 or asn == 65535 or asn == _ASN_MAX:
        return "保留 ASN 不在查询范围。"
    if asn > _ASN_MAX:
        return "ASN 超出 32 位范围 (0–4294967295)。"
    if 64512 <= asn <= 65534:
        return "16 位私有 ASN (64512–65534) 不在查询范围。"
    if 4_200_000_000 <= asn <= 4_294_967_294:
        return "32 位私有 ASN (4200000000–4294967294) 不在查询范围。"
    if 64496 <= asn <= 64511 or 65536 <= asn <= 65551:
        return "文档/示例用 ASN 不在查询范围。"
    return None


def _format_asn_reply(asn: int, data: dict[str, Any]) -> str:
    """Render the bgpview ASN payload as a Chinese plain-text summary."""

    def pick(key: str) -> str:
        value = data.get(key)
        if value is None or value == "":
            return "-"
        return str(value)

    rir = data.get("rir_allocation") or {}
    rir_name = rir.get("rir_name") or "-"
    allocated = rir.get("date_allocated") or "-"
    if isinstance(allocated, str) and " " in allocated:
        allocated = allocated.split(" ", 1)[0]  # YYYY-MM-DD only

    lines = [
        f"查询 ASN: AS{asn}",
        f"名称: {pick('name')}",
        f"描述: {pick('description_short')}",
        f"国家: {pick('country_code')}",
        f"网站: {pick('website')}",
        f"流量估算: {pick('traffic_estimation')}",
        f"流量比例: {pick('traffic_ratio')}",
        f"RIR: {rir_name}",
        f"分配日期: {allocated}",
    ]
    return "\n".join(lines)
