"""IP / domain geolocation plugin for AstrBot.

Registers a `/ip <地址>` command that queries ip-api.com and returns a Chinese
formatted summary (country, region, city, ISP, ASN, timezone, coordinates).
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


class IpQueryPlugin(Star):
    """`/ip <ip|domain>` -> Chinese geolocation summary."""

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
                logger.exception("[IpQuery] failed to close aiohttp session")
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
                "[IpQuery] 输入无效: 仅支持 IPv4 / IPv6 / 域名。"
            )
            return

        reject_reason = _reject_reserved_ip(target)
        if reject_reason is not None:
            yield event.plain_result(f"[IpQuery] 拒绝查询: {reject_reason}")
            return

        if self._session is None:
            yield event.plain_result("[IpQuery] 插件未就绪，请稍后再试。")
            return

        # ip-api.com path segment expects bare IPv6 (no [] wrapper).
        query = target[1:-1] if target.startswith("[") and target.endswith("]") else target
        try:
            async with self._session.get(
                _API_URL.format(query=query), params=_API_PARAMS
            ) as resp:
                if resp.status != 200:
                    yield event.plain_result(
                        f"[IpQuery] 上游接口异常: HTTP {resp.status}"
                    )
                    return
                data: dict[str, Any] = await resp.json(content_type=None)
        except asyncio.TimeoutError:
            yield event.plain_result("[IpQuery] 查询超时，请稍后再试。")
            return
        except aiohttp.ClientError as exc:
            logger.warning("[IpQuery] network error for %r: %s", target, exc)
            yield event.plain_result(f"[IpQuery] 网络错误: {exc}")
            return
        except ValueError as exc:
            logger.warning("[IpQuery] invalid JSON for %r: %s", target, exc)
            yield event.plain_result("[IpQuery] 上游返回数据无法解析。")
            return

        if data.get("status") != "success":
            reason = data.get("message") or "未知错误"
            yield event.plain_result(f"[IpQuery] 查询失败: {reason}")
            return

        yield event.plain_result(_format_reply(target, data))


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
