"""Parameter extractor — discovers hidden and visible parameters with minimal false positives."""

import re
from urllib.parse import parse_qs, urlparse

from ..models import Finding, FindingType, Severity


# ── Exclusions ───────────────────────────────────────────────────────────────

EXCLUDED_PARAMS = {
    # UTM and tracking
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_cid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid",
    # Common non-interesting
    "ref", "source", "from", "back", "return", "redirect", "next", "prev",
    "page", "per_page", "offset", "limit", "skip", "count",
    "sort", "order", "dir", " asc", "desc",
    "v", "t", "s", "id", "lang", "locale", "format", "type", "action",
    "callback", "jsonp", "nocache", "_", "timestamp", "rand", "random",
    # Technical
    "version", "ver", "v_", "debug", "test", "mode", "format", "output",
    "response_type", "grant_type", "client_id", "client_secret",
    # Common framework
    "_token", "_method", "_csrf", "csrf_token", "csrfmiddlewaretoken",
    "__RequestVerificationToken", "authenticity_token",
    # Common libraries
    "q", "query", "search", "keyword", "keywords",
    # HTML/CSS attributes that look like params
    "class", "style", "data-", "aria-", "role", "tabindex", "href",
    "src", "alt", "title", "placeholder", "required", "disabled",
    "checked", "selected", "multiple", "readonly", "autofocus",
    "autocomplete", "pattern", "min", "max", "step", "minlength", "maxlength",
    "name", "id", "value", "type", "for", "label",
    # Common non-interesting form params
    "utf8", "_method", "authenticity_token", "commit",
    # Referral/tracking
    "ref_cta", "ref_loc", "ref_page", "ref", "source", "from",
    # Image/media params
    "w", "h", "fm", "q", "fit", "crop", "auto",
    # AMP params
    "amp;utm_campaign", "amp;utm_medium", "amp;utm_source", "amp;utm_content",
    "amp;ref_loc", "amp;ref_page", "amp;source", "amp;ct", "amp;st",
    "amp;is_emu_login", "amp;mobile_ios", "amp;locale", "amp;v",
    # GitHub-specific
    "cft", "tags", "with", "disable_signup",
}

EXCLUDED_NAMES = {
    "width", "height", "max", "min", "size", "scale", "zoom",
    "top", "left", "right", "bottom", "x", "y", "z",
    "opacity", "alpha", "red", "green", "blue", "color",
    "padding", "margin", "border", "radius", "gap",
    "font", "font-size", "font-weight", "line-height",
    "display", "position", "float", "clear", "overflow",
    "cursor", "pointer", "hover", "focus", "active",
    "animation", "transition", "transform", "duration",
    # GitHub-specific noise
    "query-builder-test", "include_email", "javascript-support",
    "webauthn-support", "webauthn-conditional", "webauthn-iuvpaa-support",
    "required_field_f2a", "timestamp_secret", "add_account",
}


def extract_parameters(html: str, url: str) -> list[Finding]:
    findings = []
    seen = set()

    # ── Form inputs (with full context) ──────────────────────────────────
    form_pattern = re.compile(
        r"""<input[^>]+(?:name|id)=["']([^"']+)["'][^>]*>""",
        re.IGNORECASE,
    )
    for match in form_pattern.finditer(html):
        param = match.group(1)
        if param.lower() in EXCLUDED_PARAMS or param.lower() in EXCLUDED_NAMES:
            continue
        if param.startswith("_") and len(param) < 20:
            continue  # Skip internal framework params
        if param not in seen:
            seen.add(param)
            tag = match.group(0).lower()
            is_hidden = "hidden" in tag
            is_file = "file" in tag
            is_password = "password" in tag

            severity = Severity.INFO
            if is_hidden:
                severity = Severity.MEDIUM
            if is_password:
                severity = Severity.LOW
            if is_file:
                severity = Severity.LOW

            findings.append(Finding(
                type=FindingType.PARAMETER,
                url=url,
                value=param,
                source="form_input",
                severity=severity,
                context=match.group(0)[:100],
                metadata={
                    "hidden": is_hidden,
                    "file_upload": is_file,
                    "password": is_password,
                },
            ))

    # ── Query parameters from URLs in HTML ───────────────────────────────
    url_pattern = re.compile(r'(?:https?://[^\s"\'<>]+|/[^\s"\'<>]+\?[^\s"\'<>]+)')
    for url_match in url_pattern.finditer(html):
        try:
            parsed = urlparse(url_match.group(0))
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    if param.lower() in EXCLUDED_PARAMS:
                        continue
                    if param not in seen:
                        seen.add(param)
                        findings.append(Finding(
                            type=FindingType.PARAMETER,
                            url=url,
                            value=param,
                            source="url_query",
                            severity=Severity.INFO,
                            context=f"{param}={params[param][0][:30]}",
                        ))
        except Exception:
            pass

    # ── JSON body parameters in fetch/axios ───────────────────────────────
    fetch_pattern = re.compile(
        r"""(?:fetch|axios\.(?:post|put|patch))\s*\([^)]*,\s*\{([\s\S]{1,500}?)\}""",
        re.IGNORECASE,
    )
    for match in fetch_pattern.finditer(html):
        body = match.group(1)
        # Extract JSON keys
        key_pattern = re.compile(r"""["']?(\w+)["']?\s*:""")
        for key_match in key_pattern.finditer(body):
            param = key_match.group(1)
            if param.lower() in EXCLUDED_PARAMS or param.lower() in EXCLUDED_NAMES:
                continue
            if param not in seen:
                seen.add(param)
                findings.append(Finding(
                    type=FindingType.PARAMETER,
                    url=url,
                    value=param,
                    source="json_body",
                    severity=Severity.LOW,
                    context=match.group(0)[:100],
                ))

    # ── localStorage/sessionStorage keys ──────────────────────────────────
    storage_pattern = re.compile(
        r"""(?:localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\s*\(\s*['"`]([^'"]+)['"`]""",
        re.IGNORECASE,
    )
    for match in storage_pattern.finditer(html):
        key = match.group(1)
        if key.lower() in EXCLUDED_PARAMS or key.lower() in EXCLUDED_NAMES:
            continue
        if key not in seen:
            seen.add(key)
            findings.append(Finding(
                type=FindingType.PARAMETER,
                url=url,
                value=key,
                source="browser_storage",
                severity=Severity.MEDIUM,
                context=match.group(0)[:100],
            ))

    # ── URL path parameters ──────────────────────────────────────────────
    path_param_pattern = re.compile(r'(?<=/)\{(\w+)\}|(?<=/):(\w+)(?=[/?#]|$)')
    for match in path_param_pattern.finditer(html):
        param = match.group(1) or match.group(2)
        if param and param.lower() not in EXCLUDED_PARAMS:
            if param not in seen:
                seen.add(param)
                findings.append(Finding(
                    type=FindingType.PARAMETER,
                    url=url,
                    value=param,
                    source="path_parameter",
                    severity=Severity.INFO,
                    context=match.group(0)[:100],
                ))

    # ── Header parameters (interesting for auth bypass) ──────────────────
    header_pattern = re.compile(
        r"""(?:X-[\w-]+-Token|X-[\w-]+-Key|Authorization|X-Api-Key|X-Auth-Token|X-CSRF-Token)\s*[=:]\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    )
    for match in header_pattern.finditer(html):
        value = match.group(1)
        header_name = match.group(0).split(":")[0].split("=")[0].strip()
        if value not in seen and len(value) > 5:
            seen.add(value)
            findings.append(Finding(
                type=FindingType.PARAMETER,
                url=url,
                value=f"{header_name}: {value[:50]}",
                source="header_parameter",
                severity=Severity.MEDIUM,
                context=match.group(0)[:100],
                metadata={"header": header_name},
            ))

    return findings
