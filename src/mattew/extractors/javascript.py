"""JavaScript extractor — finds JS files and inline script insights."""

import re
from urllib.parse import urljoin

from ..models import Finding, FindingType, Severity


def extract_javascript(html: str, base_url: str) -> list[Finding]:
    findings = []
    seen = set()

    # <script src="...">
    src_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in src_pattern.finditer(html):
        src = match.group(1).strip()
        full = urljoin(base_url, src)
        if full not in seen:
            seen.add(full)
            findings.append(Finding(
                type=FindingType.JAVASCRIPT,
                url=base_url,
                value=full,
                source="script_src",
                context=match.group(0)[:100],
            ))

    # Dynamic imports
    import_pattern = re.compile(
        r"""import\(['"`]([^'"`]+)['"`]\)|"""
        r"""require\(['"`]([^'"`]+)['"`]\)""",
        re.IGNORECASE,
    )
    for match in import_pattern.finditer(html):
        path = match.group(1) or match.group(2)
        if path and not path.startswith(("http://", "https://")):
            path = urljoin(base_url, path)
        if path and path not in seen:
            seen.add(path)
            findings.append(Finding(
                type=FindingType.JAVASCRIPT,
                url=base_url,
                value=path,
                source="dynamic_import",
                context=match.group(0)[:100],
            ))

    # Inline script size indicator (large inline scripts are interesting)
    inline_pattern = re.compile(r'<script(?![^>]*src=)[^>]*>([\s\S]{500,}?)</script>', re.IGNORECASE)
    for match in inline_pattern.finditer(html):
        script_content = match.group(1)
        # Look for interesting patterns inside inline scripts
        interesting = []
        if re.search(r'window\.\w+\s*=', script_content):
            interesting.append("window_assignments")
        if re.search(r'document\.cookie', script_content):
            interesting.append("cookie_access")
        if re.search(r'localStorage|sessionStorage', script_content):
            interesting.append("storage_access")
        if re.search(r'eval\(', script_content):
            interesting.append("eval_usage")

        if interesting:
            findings.append(Finding(
                type=FindingType.JAVASCRIPT,
                url=base_url,
                value=f"inline_script ({', '.join(interesting)})",
                source="inline_script_analysis",
                severity=Severity.MEDIUM if "eval_usage" in interesting else Severity.INFO,
                context=script_content[:200],
                metadata={"length": len(script_content), "flags": interesting},
            ))

    return findings
