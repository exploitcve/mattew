"""API route extractor — comprehensive API discovery."""

import re
from urllib.parse import urljoin

from ..models import Finding, FindingType, Severity


def extract_api_routes(html: str, base_url: str) -> list[Finding]:
    findings = []
    seen = set()

    # ── WordPress REST API ────────────────────────────────────────────────
    wp_api_pattern = re.compile(
        r"""['"`](https?://[^'"`]*wp-json[^'"`]*)['"`]""",
        re.IGNORECASE,
    )
    for match in wp_api_pattern.finditer(html):
        url = match.group(1)
        if url not in seen:
            seen.add(url)
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=base_url, value=url,
                source="wordpress_rest_api", severity=Severity.LOW,
                context=f"WordPress REST API: {url[:80]}",
            ))

    # WP REST API paths
    wp_path_pattern = re.compile(
        r"""['"`](/wp-json/[^'"`]+)['"`]""",
        re.IGNORECASE,
    )
    for match in wp_path_pattern.finditer(html):
        path = match.group(1)
        full = urljoin(base_url, path)
        if full not in seen:
            seen.add(full)
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=base_url, value=full,
                source="wordpress_rest_api", severity=Severity.LOW,
                context=f"WP REST: {path[:60]}",
            ))

    # ── REST API paths (v1, v2, api/, etc.) ──────────────────────────────
    rest_pattern = re.compile(
        r"""['"`](/(?:api|v[0-9]+|graphql|rest|internal|admin|auth|login|register|logout|upload|download|search|users?|accounts?|settings?|config|health|status|metrics|debug|test)/[a-zA-Z0-9/_-]*)['"`]""",
        re.IGNORECASE,
    )
    for match in rest_pattern.finditer(html):
        path = match.group(1)
        full = urljoin(base_url, path)
        if full not in seen:
            seen.add(full)
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=base_url, value=full,
                source="rest_api_path", severity=Severity.LOW,
                context=f"REST path: {path[:60]}",
            ))

    # ── API URLs in link/meta tags ───────────────────────────────────────
    api_link_pattern = re.compile(
        r"""(?:href|src|content)=["'](https?://[^"']*(?:api|rest|graphql|endpoint)[^"']*)["']""",
        re.IGNORECASE,
    )
    for match in api_link_pattern.finditer(html):
        url = match.group(1)
        if url not in seen:
            seen.add(url)
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=base_url, value=url,
                source="api_link_tag", severity=Severity.LOW,
                context=f"API link: {url[:80]}",
            ))

    # ── GraphQL endpoints ─────────────────────────────────────────────────
    graphql_pattern = re.compile(
        r"""['"`]([^'"`]*graphql[^'"`]*)['"`]""",
        re.IGNORECASE,
    )
    for match in graphql_pattern.finditer(html):
        path = match.group(1)
        if not path.startswith(("http://", "https://")):
            path = urljoin(base_url, path)
        if path not in seen:
            seen.add(path)
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=base_url, value=path,
                source="graphql_reference", severity=Severity.MEDIUM,
                context=f"GraphQL: {path[:60]}",
            ))

    # ── WebSocket connections ─────────────────────────────────────────────
    ws_pattern = re.compile(r"""(?:wss?://[^\s'"]+)""", re.IGNORECASE)
    for match in ws_pattern.finditer(html):
        url = match.group(0)
        if url not in seen:
            seen.add(url)
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=base_url, value=url,
                source="websocket", severity=Severity.LOW,
                context=f"WebSocket: {url[:60]}",
            ))

    # ── API base URLs in config ──────────────────────────────────────────
    config_pattern = re.compile(
        r"""(?:baseUrl|baseURL|apiUrl|apiBase|endpoint|apiEndpoint|API_URL|API_BASE|api_url|api_base)"""
        r"""[\s]*[=:]\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    )
    for match in config_pattern.finditer(html):
        url = match.group(1).strip()
        if not url.startswith(("http://", "https://", "/")):
            url = "/" + url
        if url.startswith("/"):
            url = urljoin(base_url, url)
        if url not in seen:
            seen.add(url)
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=base_url, value=url,
                source="config_object", severity=Severity.MEDIUM,
                context=f"Config API: {url[:60]}",
            ))

    # ── Fetch/XHR calls in scripts ───────────────────────────────────────
    fetch_pattern = re.compile(
        r"""(?:fetch\s*\(|\.get\s*\(|\.post\s*\(|\.put\s*\(|\.delete\s*\(|\.patch\s*\()"""
        r"""[\s\S]{0,30}?['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    )
    for match in fetch_pattern.finditer(html):
        path = match.group(1).strip()
        if path.startswith(("javascript:", "mailto:", "data:")):
            continue
        if "." not in path and "/" not in path:
            continue
        if path.startswith(("http://", "https://")):
            full = path
        else:
            full = urljoin(base_url, path)
        if full not in seen:
            seen.add(full)
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=base_url, value=full,
                source="fetch_call", severity=Severity.LOW,
                context=f"Fetch: {path[:60]}",
            ))

    # ── XMLHttpRequest patterns ──────────────────────────────────────────
    xhr_pattern = re.compile(
        r"""XMLHttpRequest[\s\S]{0,30}?['"`](https?://[^'"`]+)['"`]""",
        re.IGNORECASE,
    )
    for match in xhr_pattern.finditer(html):
        url = match.group(1)
        if url not in seen:
            seen.add(url)
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=base_url, value=url,
                source="xhr_request", severity=Severity.LOW,
                context=f"XHR: {url[:60]}",
            ))

    return findings
