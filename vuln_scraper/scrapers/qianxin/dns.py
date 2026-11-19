from ipaddress import IPv4Address

import httpx

from vuln_scraper.client import FetchError
from vuln_scraper.scrapers.qianxin.config import HOSTNAME


async def resolve_dns(hostname: str) -> tuple[str, int] | None:
    if hostname != HOSTNAME:
        return None

    # Qianxin's international CDN alias can return NXDOMAIN. A DNS query
    # scoped to a public mainland resolver's subnet returns the vendor's
    # mainland route, without sending information about the user's subnet.
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get("https://dns.google/resolve", params={
                "name": HOSTNAME, "type": "A", "edns_client_subnet": "114.114.114.0/24",
            })
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise FetchError(f"DNS fallback for {HOSTNAME} failed: {exc}") from exc

    answers = payload.get("Answer") if isinstance(payload, dict) and payload.get("Status") == 0 else []
    if not isinstance(answers, list):
        answers = []
    for answer in answers:
        if not isinstance(answer, dict) or answer.get("type") != 1:
            continue
        value = answer.get("data")
        if not isinstance(value, str):
            continue
        try:
            address = IPv4Address(value)
        except ValueError:
            continue
        if address.is_global and not address.is_multicast:
            ttl = answer.get("TTL")
            return str(address), max(0, ttl) if isinstance(ttl, int) else 0

    raise FetchError(f"DNS fallback returned no public IPv4 address for {HOSTNAME}")
