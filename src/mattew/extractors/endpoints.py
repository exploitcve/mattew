"""Endpoint extractor — discovers URLs and paths from HTML/JS."""

import re
from urllib.parse import urljoin, urlparse

from ..models import Finding, FindingType, Severity


def extract_endpoints(html: str, base_url: str) -> list[Finding]:
    findings = []
    seen = set()

    # href, src, action, data-url attributes
    attr_pattern = re.compile(
        r"""(?:href|src|action|data-url|data-action|data-endpoint|data-api)"""
        r"""=\s*["']([^"'#]+)["']""",
        re.IGNORECASE,
    )
    for match in attr_pattern.finditer(html):
        url = match.group(1).strip()
        if url.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        full = urljoin(base_url, url)
        if full not in seen:
            seen.add(full)
            findings.append(Finding(
                type=FindingType.ENDPOINT,
                url=base_url,
                value=full,
                source="html_attribute",
                context=match.group(0)[:100],
            ))

    # Fetch/XHR patterns in inline scripts (must be actual function calls, not HTML attributes)
    fetch_pattern = re.compile(
        r"""(?:fetch\s*\(|\.get\s*\(|\.post\s*\(|\.put\s*\(|\.delete\s*\(|\.patch\s*\(|\.ajax\s*\(|XMLHttpRequest)"""
        r"""[\s\S]{0,30}?['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    )
    for match in fetch_pattern.finditer(html):
        path = match.group(1).strip()
        # Skip non-URL patterns
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
                type=FindingType.API_ROUTE,
                url=base_url,
                value=full,
                source="inline_script",
                severity=Severity.LOW,
                context=match.group(0)[:100],
            ))

    # Template literal endpoints
    template_pattern = re.compile(
        r"""['"`]/((?:api|v[0-9]+|graphql|rest)/[^'"`\s${}]+)['"`]""",
        re.IGNORECASE,
    )
    for match in template_pattern.finditer(html):
        path = "/" + match.group(1)
        full = urljoin(base_url, path)
        if full not in seen:
            seen.add(full)
            findings.append(Finding(
                type=FindingType.API_ROUTE,
                url=base_url,
                value=full,
                source="template_literal",
                severity=Severity.LOW,
                context=match.group(0)[:100],
            ))

    return findings
