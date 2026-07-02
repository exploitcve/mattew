"""Security analyzer — headers, CORS, cookies, sensitive files, WAF detection."""

import re
from urllib.parse import urljoin

from ..models import Finding, FindingType, Severity


# ── Security header checks ──────────────────────────────────────────────────

REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": Severity.HIGH,
        "description": "HSTS not set — vulnerable to protocol downgrade",
        "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "severity": Severity.HIGH,
        "description": "CSP not set — vulnerable to XSS",
        "recommendation": "Implement a Content-Security-Policy header",
    },
    "x-content-type-options": {
        "severity": Severity.MEDIUM,
        "description": "X-Content-Type-Options not set — MIME sniffing possible",
        "recommendation": "Add X-Content-Type-Options: nosniff",
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options not set — clickjacking possible",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-xss-protection": {
        "severity": Severity.LOW,
        "description": "X-XSS-Protection not set (legacy but still useful for older browsers)",
        "recommendation": "Add X-XSS-Protection: 1; mode=block",
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy not set — referrer leakage possible",
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy not set — browser features unrestricted",
        "recommendation": "Add Permissions-Policy to restrict camera, microphone, geolocation, etc.",
    },
}


def check_security_headers(headers: dict[str, str], url: str) -> list[Finding]:
    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header, info in REQUIRED_SECURITY_HEADERS.items():
        if header not in lower_headers:
            findings.append(Finding(
                type=FindingType.HEADER,
                url=url,
                value=header,
                source="missing_security_header",
                severity=info["severity"],
                context=info["description"],
                metadata={
                    "header": header,
                    "recommendation": info["recommendation"],
                    "present": False,
                },
            ))
        else:
            value = lower_headers[header]
            # Check for weak configurations
            if header == "strict-transport-security" and "max-age=0" in value:
                findings.append(Finding(
                    type=FindingType.HEADER,
                    url=url,
                    value=f"{header}: {value}",
                    source="weak_security_header",
                    severity=Severity.HIGH,
                    context="HSTS max-age is 0 — effectively disabled",
                    metadata={"header": header, "value": value, "present": True},
                ))
            elif header == "x-frame-options" and value.upper() == "ALLOW-FROM":
                findings.append(Finding(
                    type=FindingType.HEADER,
                    url=url,
                    value=f"{header}: {value}",
                    source="weak_security_header",
                    severity=Severity.MEDIUM,
                    context="X-Frame-Options ALLOW-FROM is deprecated",
                    metadata={"header": header, "value": value, "present": True},
                ))

    return findings


# ── CORS analysis ────────────────────────────────────────────────────────────

def check_cors(headers: dict[str, str], url: str) -> list[Finding]:
    findings = []
    acao = headers.get("Access-Control-Allow-Origin", "")

    if acao == "*":
        findings.append(Finding(
            type=FindingType.HEADER,
            url=url,
            value="Access-Control-Allow-Origin: *",
            source="cors_wildcard",
            severity=Severity.MEDIUM,
            context="CORS wildcard — any origin can read responses",
            metadata={"header": "Access-Control-Allow-Origin", "value": acao},
        ))

    if acao and acao != "*":
        acac = headers.get("Access-Control-Allow-Credentials", "")
        if acac.lower() == "true":
            findings.append(Finding(
                type=FindingType.HEADER,
                url=url,
                value=f"ACA-Origin: {acao}, ACA-Credentials: true",
                source="cors_credentials",
                severity=Severity.HIGH,
                context="CORS allows credentials with specific origin — check for origin reflection",
                metadata={
                    "origin": acao,
                    "credentials": True,
                },
            ))

    return findings


# ── Cookie analysis ──────────────────────────────────────────────────────────

def check_cookies(headers: dict[str, str], url: str) -> list[Finding]:
    findings = []
    # Case-insensitive header lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}
    set_cookies = lower_headers.get("set-cookie", "")

    if not set_cookies:
        return findings

    # Split multiple Set-Cookie headers (they may be joined with \n)
    cookies = [c.strip() for c in set_cookies.split("\n") if c.strip()]

    for cookie in cookies:
        name = cookie.split("=")[0].strip() if "=" in cookie else ""
        lower = cookie.lower()

        issues = []
        if "secure" not in lower:
            issues.append("missing Secure flag")
        if "httponly" not in lower:
            issues.append("missing HttpOnly flag")
        if "samesite" not in lower:
            issues.append("missing SameSite attribute")

        if issues:
            findings.append(Finding(
                type=FindingType.HEADER,
                url=url,
                value=f"Cookie: {name}",
                source="cookie_analysis",
                severity=Severity.MEDIUM if len(issues) >= 2 else Severity.LOW,
                context=f"{name}: {', '.join(issues)}",
                metadata={
                    "cookie_name": name,
                    "issues": issues,
                    "full_cookie": cookie[:200],
                },
            ))

        # Session cookie detection
        session_indicators = ["session", "sid", "token", "auth", "jwt", "sess"]
        if any(ind in name.lower() for ind in session_indicators):
            if "secure" not in lower or "httponly" not in lower:
                findings.append(Finding(
                    type=FindingType.HEADER,
                    url=url,
                    value=f"Session cookie: {name}",
                    source="insecure_session_cookie",
                    severity=Severity.HIGH,
                    context=f"Session-related cookie '{name}' missing security flags",
                    metadata={"cookie_name": name, "full_cookie": cookie[:200]},
                ))

    return findings


# ── Sensitive file discovery ─────────────────────────────────────────────────

SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.DS_Store",
    "/.htaccess",
    "/.htpasswd",
    "/wp-config.php.bak",
    "/wp-config.php.save",
    "/wp-config.php~",
    "/wp-config.php.old",
    "/config.php.bak",
    "/config.php.save",
    "/database.sql",
    "/database.sql.gz",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/site.tar.gz",
    "/www.zip",
    "/public.zip",
    "/.aws/credentials",
    "/.ssh/authorized_keys",
    "/docker-compose.yml",
    "/Dockerfile",
    "/package-lock.json",
    "/yarn.lock",
    "/composer.lock",
    "/.npmrc",
    "/server.key",
    "/server.crt",
    "/cert.pem",
    "/key.pem",
    "/debug.log",
    "/error.log",
    "/access.log",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/admin/",
    "/administrator/",
    "/phpmyadmin/",
    "/adminer.php",
    "/console",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/swagger.json",
    "/swagger-ui/",
    "/api-docs",
    "/openapi.json",
    "/graphql",
    "/_debugToolbar/",
    "/elmah.axd",
    "/trace.axd",
    "/web.config",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/",
]


def find_sensitive_files(html: str, base_url: str) -> list[Finding]:
    findings = []
    seen = set()

    # Check referenced sensitive paths in HTML
    for path in SENSITIVE_PATHS:
        full_url = urljoin(base_url, path)
        if full_url in seen:
            continue
        seen.add(full_url)

        # Check if path is referenced in the HTML
        if path.lower() in html.lower():
            severity = Severity.HIGH
            if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/crossdomain.xml"):
                severity = Severity.INFO
            elif path.endswith((".lock", ".json")):
                severity = Severity.MEDIUM

            findings.append(Finding(
                type=FindingType.FILE,
                url=base_url,
                value=full_url,
                source="sensitive_file_reference",
                severity=severity,
                context=f"Sensitive path '{path}' referenced in HTML",
                metadata={"path": path},
            ))

    # Check for .env patterns in JS/HTML
    env_pattern = re.compile(r'(?:process\.env\.|import\.meta\.env\.)(\w+)')
    env_vars = set(env_pattern.findall(html))
    for var in env_vars:
        if var not in seen:
            seen.add(var)
            findings.append(Finding(
                type=FindingType.SECRET,
                url=base_url,
                value=f"process.env.{var}",
                source="env_reference",
                severity=Severity.MEDIUM,
                context=f"Environment variable reference found: process.env.{var}",
                metadata={"variable": var},
            ))

    return findings


# ── WAF detection ────────────────────────────────────────────────────────────

WAF_SIGNATURES = [
    (r"cloudflare", "Cloudflare"),
    (r"incapsula|imperva", "Incapsula/Imperva"),
    (r"akamaighost", "Akamai"),
    (r"awselb|aws.*waf", "AWS WAF"),
    (r"Sucuri", "Sucuri"),
    (r"Wordfence", "Wordfence"),
    (r"ModSecurity", "ModSecurity"),
    (r"X-CDN:\s*Incapsula", "Incapsula"),
    (r"X-Sucuri-ID", "Sucuri"),
    (r"X-protected-by", "Generic WAF"),
    (r"x-cdn:\s*StackPath", "StackPath"),
    (r"x-sucuri-cache", "Sucuri Cache"),
    (r"server.*bigip|BIGip", "F5 BIG-IP"),
    (r"x-aspnetmvc.*version", "ASP.NET (WAF possible)"),
]


def detect_waf(headers: dict[str, str], html: str) -> list[Finding]:
    findings = []
    combined = "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + html

    for pattern, waf_name in WAF_SIGNATURES:
        if re.search(pattern, combined, re.IGNORECASE):
            findings.append(Finding(
                type=FindingType.INFO,
                url="",
                value=f"WAF detected: {waf_name}",
                source="waf_detection",
                severity=Severity.INFO,
                context=f"Web Application Firewall identified via pattern: {pattern}",
                metadata={"waf": waf_name},
            ))
            break  # Only report one WAF

    return findings


# ── Source map discovery ─────────────────────────────────────────────────────

def find_source_maps(html: str, base_url: str) -> list[Finding]:
    findings = []

    # sourceMappingURL comments
    sourcemap_pattern = re.compile(r'//#\s*sourceMappingURL=(\S+)')
    for match in sourcemap_pattern.finditer(html):
        url = match.group(1)
        if not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)
        findings.append(Finding(
            type=FindingType.FILE,
            url=base_url,
            value=url,
            source="source_map",
            severity=Severity.MEDIUM,
            context=f"Source map exposed: {match.group(0)}",
            metadata={"type": "sourceMappingURL"},
        ))

    # .map file references
    map_pattern = re.compile(r'["\']([^"\']*\.js\.map)["\']')
    for match in map_pattern.finditer(html):
        url = match.group(1)
        if not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)
        findings.append(Finding(
            type=FindingType.FILE,
            url=base_url,
            value=url,
            source="source_map_reference",
            severity=Severity.MEDIUM,
            context=f"JS source map file referenced: {match.group(0)}",
            metadata={"type": "js_map_file"},
        ))

    return findings


# ── Robots.txt / Sitemap analysis ───────────────────────────────────────────

def analyze_robots_txt(content: str, base_url: str) -> list[Finding]:
    findings = []

    # Disallowed paths — interesting for attack surface
    disallow_pattern = re.compile(r'Disallow:\s*(.+)', re.IGNORECASE)
    disallowed = []
    for match in disallow_pattern.finditer(content):
        path = match.group(1).strip()
        if path and path != "/":
            disallowed.append(path)
            findings.append(Finding(
                type=FindingType.ENDPOINT,
                url=base_url,
                value=urljoin(base_url, path),
                source="robots_disallow",
                severity=Severity.LOW,
                context=f"Blocked by robots.txt: Disallow: {path}",
            ))

    # Sitemap references
    sitemap_pattern = re.compile(r'Sitemap:\s*(\S+)', re.IGNORECASE)
    for match in sitemap_pattern.finditer(content):
        findings.append(Finding(
            type=FindingType.ENDPOINT,
            url=base_url,
            value=match.group(1),
            source="robots_sitemap",
            severity=Severity.INFO,
            context=f"Sitemap reference: {match.group(0)}",
        ))

    # Interesting paths in comments
    comment_pattern = re.compile(r'#\s*(.+)')
    for match in comment_pattern.finditer(content):
        text = match.group(1).strip()
        if any(kw in text.lower() for kw in ["api", "admin", "debug", "test", "internal", " staging"]):
            findings.append(Finding(
                type=FindingType.INFO,
                url=base_url,
                value=text,
                source="robots_comment",
                severity=Severity.LOW,
                context=f"Interesting robots.txt comment: {text}",
            ))

    return findings


# ── CSP analysis ─────────────────────────────────────────────────────────────

def analyze_csp(csp: str, url: str) -> list[Finding]:
    findings = []

    if not csp:
        return findings

    # Check for unsafe-inline
    if "unsafe-inline" in csp:
        findings.append(Finding(
            type=FindingType.HEADER,
            url=url,
            value="CSP: unsafe-inline",
            source="csp_weakness",
            severity=Severity.MEDIUM,
            context="CSP allows unsafe-inline — XSS via inline scripts possible",
            metadata={"directive": "unsafe-inline"},
        ))

    # Check for unsafe-eval
    if "unsafe-eval" in csp:
        findings.append(Finding(
            type=FindingType.HEADER,
            url=url,
            value="CSP: unsafe-eval",
            source="csp_weakness",
            severity=Severity.HIGH,
            context="CSP allows unsafe-eval — XSS via eval() possible",
            metadata={"directive": "unsafe-eval"},
        ))

    # Check for wildcard in script-src
    if re.search(r"script-src\s+[^;]*\*", csp):
        findings.append(Finding(
            type=FindingType.HEADER,
            url=url,
            value="CSP: script-src *",
            source="csp_wildcard",
            severity=Severity.HIGH,
            context="CSP script-src allows wildcard — effectively no script restriction",
            metadata={"directive": "script-src *"},
        ))

    # Check for data: in script-src
    if re.search(r"script-src\s+[^;]*data:", csp):
        findings.append(Finding(
            type=FindingType.HEADER,
            url=url,
            value="CSP: script-src data:",
            source="csp_weakness",
            severity=Severity.HIGH,
            context="CSP allows data: URIs in scripts — XSS vector",
            metadata={"directive": "script-src data:"},
        ))

    # Check for missing base-uri
    if "base-uri" not in csp:
        findings.append(Finding(
            type=FindingType.HEADER,
            url=url,
            value="CSP: missing base-uri",
            source="csp_missing",
            severity=Severity.LOW,
            context="CSP missing base-uri directive — base tag injection possible",
            metadata={"directive": "base-uri"},
        ))

    return findings
