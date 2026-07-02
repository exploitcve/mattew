"""API route extractor — discovers API patterns from page content."""

import re
from urllib.parse import urljoin

from ..models import Finding, FindingType, Severity


def extract_api_routes(html: str, base_url: str) -> list[Finding]:
    findings = []
    seen = set()

    # REST-like paths
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
                type=FindingType.API_ROUTE,
                url=base_url,
                value=full,
                source="js_string_literal",
                severity=Severity.LOW,
                context=match.group(0)[:100],
            ))

    # GraphQL endpoints
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
                type=FindingType.API_ROUTE,
                url=base_url,
                value=path,
                source="graphql_reference",
                severity=Severity.MEDIUM,
                context=match.group(0)[:100],
            ))

    # WebSocket connections
    ws_pattern = re.compile(
        r"""(?:wss?://[^\s'"]+)""",
        re.IGNORECASE,
    )
    for match in ws_pattern.finditer(html):
        url = match.group(0)
        if url not in seen:
            seen.add(url)
            findings.append(Finding(
                type=FindingType.API_ROUTE,
                url=base_url,
                value=url,
                source="websocket",
                severity=Severity.LOW,
                context=match.group(0)[:100],
            ))

    # API base URLs in config objects
    config_pattern = re.compile(
        r"""(?:baseUrl|baseURL|apiUrl|apiBase|endpoint|apiEndpoint|API_URL|API_BASE)"""
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
                type=FindingType.API_ROUTE,
                url=base_url,
                value=url,
                source="config_object",
                severity=Severity.MEDIUM,
                context=match.group(0)[:100],
            ))

    return findings
