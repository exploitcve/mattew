"""Bug bounty attack surface analyzer — comprehensive findings for hunters."""

import re
import base64
import json
from urllib.parse import urljoin, urlparse, parse_qs

from ..models import Finding, FindingType, Severity


# ── Directory listing detection ──────────────────────────────────────────────

def check_directory_listing(html: str, url: str) -> list[Finding]:
    findings = []
    indicators = [
        r"<title>Index of /", r"<h1>Index of /", r"Parent Directory</a>",
        r"<pre><a href=.*?>\.\./</a>", r"Directory listing for",
        r"Apache.*at.*Port", r"nginx.*directory listing",
        r"<title>[^<]*Index of[^<]*</title>",
    ]
    for pattern in indicators:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append(Finding(
                type=FindingType.FILE, url=url, value=url,
                source="directory_listing", severity=Severity.HIGH,
                context="Directory listing — file structure exposed",
            ))
            break
    return findings


# ── Backup file detection ───────────────────────────────────────────────────

BACKUP_EXTENSIONS = [
    ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo",
    ".tmp", "~", ".copy", ".dist", ".php~", ".php.bak",
    ".php.old", ".php.save", ".php.swp", ".sql", ".sql.gz",
    ".dump", ".export", ".bak.php", ".old.php",
]

BACKUP_FILENAMES = [
    "backup.sql", "dump.sql", "database.sql", "db.sql",
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip",
    "backup.tar", "backup.rar", "backup.7z",
    "config.php.bak", "wp-config.php.bak", "settings.py.bak",
    ".env.backup", ".env.old", ".env.local", ".env.production",
    "credentials.json", "secrets.json", "service-account.json",
]


def find_backup_files(html: str, url: str) -> list[Finding]:
    findings = []
    seen = set()
    for ext in BACKUP_EXTENSIONS:
        pattern = re.compile(rf'href=["\']([^"\']*{re.escape(ext)})["\']', re.IGNORECASE)
        for match in pattern.finditer(html):
            path = match.group(1)
            full_url = urljoin(url, path)
            if full_url not in seen:
                seen.add(full_url)
                findings.append(Finding(
                    type=FindingType.FILE, url=url, value=full_url,
                    source="backup_file", severity=Severity.HIGH,
                    context=f"Backup file: {match.group(0)[:80]}",
                ))
    for filename in BACKUP_FILENAMES:
        if filename.lower() in html.lower():
            pattern = re.compile(rf'["\']([^"\']*{re.escape(filename)})["\']', re.IGNORECASE)
            match = pattern.search(html)
            if match:
                path = match.group(1)
                full_url = urljoin(url, path)
                if full_url not in seen:
                    seen.add(full_url)
                    findings.append(Finding(
                        type=FindingType.FILE, url=url, value=full_url,
                        source="backup_file", severity=Severity.HIGH,
                        context=f"Known backup: {filename}",
                    ))
    return findings


# ── Debug/admin endpoint detection ──────────────────────────────────────────

DEBUG_ENDPOINTS = [
    "/debug", "/debug/", "/debug/vars", "/debug/pprof", "/debug/requests",
    "/admin", "/admin/", "/administrator", "/adminer.php",
    "/phpinfo.php", "/info.php", "/test.php", "/php-test.php",
    "/server-status", "/server-info",
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
    "/swagger-ui", "/swagger-ui.html", "/api-docs", "/swagger.json",
    "/graphql", "/graphiql", "/playground", "/voyager",
    "/elmah.axd", "/trace.axd",
    "/metrics", "/prometheus", "/stats",
    "/console", "/_console", "/manage",
    "/phpmyadmin", "/pma", "/adminer", "/dbadmin",
    "/wp-admin", "/wp-login.php",
    "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
]


def find_debug_endpoints(html: str, url: str) -> list[Finding]:
    findings = []
    seen_endpoints = set()
    for endpoint in DEBUG_ENDPOINTS:
        if endpoint in seen_endpoints:
            continue
        escaped = re.escape(endpoint)
        pattern = re.compile(rf'["\']([^"\']*{escaped}[^"\']*)["\']', re.IGNORECASE)
        match = pattern.search(html)
        if match:
            seen_endpoints.add(endpoint)
            path = match.group(1)
            full_url = urljoin(url, path)
            severity = Severity.HIGH
            if endpoint in ("/debug", "/debug/", "/debug/vars", "/debug/pprof", "/debug/requests"):
                severity = Severity.CRITICAL
            elif endpoint in ("/.env", "/.env.local", "/.env.production", "/.env.development"):
                severity = Severity.CRITICAL
            elif "actuator" in endpoint:
                severity = Severity.CRITICAL
            findings.append(Finding(
                type=FindingType.ENDPOINT, url=url, value=full_url,
                source="debug_endpoint", severity=severity,
                context=f"Debug/admin: {endpoint}",
            ))
    return findings


# ── Open redirect detection ─────────────────────────────────────────────────

def find_open_redirects(html: str, url: str) -> list[Finding]:
    findings = []
    redirect_params = [
        "redirect", "redirect_url", "redirect_uri", "return_url", "return_to",
        "next", "continue", "dest", "destination", "redir", "redirect_to",
        "goto", "url", "link", "go", "out", "view", "to", "ref", "rurl",
        "return", "returnTo", "checkout_url", "return_uri",
    ]
    for param in redirect_params:
        pattern = re.compile(
            rf'action=["\']([^"\']*{re.escape(param)}[^"\']*)["\']', re.IGNORECASE,
        )
        for match in pattern.finditer(html):
            findings.append(Finding(
                type=FindingType.ENDPOINT, url=url,
                value=f"Open redirect form: {param}",
                source="open_redirect", severity=Severity.MEDIUM,
                context=match.group(0)[:100],
                metadata={"parameter": param, "location": "form"},
            ))
        js_pattern = re.compile(
            rf"""(?:window\.location|location\.href|location\.replace|location\.assign)\s*[=(]\s*['"`][^'"]*{re.escape(param)}[^'"]*['"`]""",
            re.IGNORECASE,
        )
        for match in js_pattern.finditer(html):
            findings.append(Finding(
                type=FindingType.ENDPOINT, url=url,
                value=f"Open redirect JS: {param}",
                source="open_redirect_js", severity=Severity.MEDIUM,
                context=match.group(0)[:100],
                metadata={"parameter": param, "location": "javascript"},
            ))
    return findings


# ── Header analysis ─────────────────────────────────────────────────────────

def analyze_interesting_headers(headers: dict[str, str], url: str) -> list[Finding]:
    findings = []
    lh = {k.lower(): v for k, v in headers.items()}

    # Information disclosure
    for header in ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                    "x-debug-token", "x-generated-by", "x-runtime"]:
        if header in lh:
            findings.append(Finding(
                type=FindingType.HEADER, url=url,
                value=f"{header}: {lh[header]}",
                source="info_disclosure", severity=Severity.LOW,
                context="Server technology disclosed",
            ))

    # Server version disclosure
    if "server" in lh:
        server = lh["server"]
        if re.search(r'[\d.]+', server):
            findings.append(Finding(
                type=FindingType.HEADER, url=url,
                value=f"Server: {server}",
                source="version_disclosure", severity=Severity.LOW,
                context="Server version disclosed",
            ))

    # Missing security headers
    critical_headers = {
        "strict-transport-security": ("HSTS missing", Severity.MEDIUM),
        "content-security-policy": ("CSP missing", Severity.MEDIUM),
        "x-content-type-options": ("X-Content-Type-Options missing", Severity.MEDIUM),
        "x-frame-options": ("X-Frame-Options missing (clickjacking)", Severity.LOW),
        "referrer-policy": ("Referrer-Policy missing", Severity.LOW),
    }
    for header, (desc, sev) in critical_headers.items():
        if header not in lh:
            findings.append(Finding(
                type=FindingType.HEADER, url=url, value=header,
                source="missing_header", severity=sev, context=desc,
            ))

    # CORS analysis
    acao = lh.get("access-control-allow-origin", "")
    if acao == "*":
        findings.append(Finding(
            type=FindingType.HEADER, url=url,
            value="CORS: Access-Control-Allow-Origin: *",
            source="cors_wildcard", severity=Severity.MEDIUM,
            context="CORS wildcard — any origin can read responses",
        ))
    elif acao:
        acac = lh.get("access-control-allow-credentials", "")
        if acac.lower() == "true":
            findings.append(Finding(
                type=FindingType.HEADER, url=url,
                value=f"CORS: {acao} + credentials",
                source="cors_credentials", severity=Severity.HIGH,
                context=f"CORS allows credentials — test with origin: https://evil.com",
                metadata={"origin": acao, "test_hint": "Send request with Origin: https://evil.com"},
            ))

    # Cookie analysis
    set_cookie = lh.get("set-cookie", "")
    if set_cookie:
        cookies = [c.strip() for c in set_cookie.split("\n") if c.strip()]
        for cookie in cookies:
            name = cookie.split("=")[0].strip()
            lc = cookie.lower()
            issues = []
            if "secure" not in lc: issues.append("no Secure")
            if "httponly" not in lc: issues.append("no HttpOnly")
            if "samesite" not in lc: issues.append("no SameSite")
            session_words = ["session", "sid", "token", "auth", "jwt", "sess"]
            is_session = any(w in name.lower() for w in session_words)
            if issues and (is_session or len(issues) >= 2):
                findings.append(Finding(
                    type=FindingType.HEADER, url=url,
                    value=f"Cookie: {name} ({', '.join(issues)})",
                    source="insecure_cookie",
                    severity=Severity.HIGH if is_session else Severity.MEDIUM,
                    context=f"Cookie '{name}' missing: {', '.join(issues)}",
                ))
    return findings


# ── JavaScript secret hunting ────────────────────────────────────────────────

def hunt_js_secrets(html: str, url: str) -> list[Finding]:
    findings = []
    seen = set()

    script_pattern = re.compile(r'<script[^>]*>([\s\S]*?)</script>', re.IGNORECASE)
    for script_match in script_pattern.finditer(html):
        content = script_match.group(1)
        if len(content) < 50:
            continue

        # Credentials in URL
        cred_pattern = re.compile(
            r"""(?:https?://)([a-zA-Z0-9._-]{3,}):([a-zA-Z0-9._-]{3,})@([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})""",
        )
        for match in cred_pattern.finditer(content):
            user, password, host = match.group(1), match.group(2), match.group(3)
            skip_users = {"user", "admin", "root", "test", "guest", "demo", "null"}
            skip_hosts = {"schema.org", "example.com", "localhost", "127.0.0.1"}
            if user.lower() in skip_users or host.lower() in skip_hosts:
                continue
            if "/" in password or "." in password:
                continue
            findings.append(Finding(
                type=FindingType.SECRET, url=url,
                value=f"Creds in URL: {user}:{password[:20]}@{host}",
                source="js_url_credentials", severity=Severity.CRITICAL,
                context=match.group(0)[:100],
            ))

        # Base64 secrets
        b64_pattern = re.compile(r"""['"`]([A-Za-z0-9+/]{50,}={0,2})['"`]""")
        for match in b64_pattern.finditer(content):
            encoded = match.group(1)
            if encoded in seen:
                continue
            seen.add(encoded)
            try:
                decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
                if any(kw in decoded.lower() for kw in ["password", "secret", "token", "key", "api", "auth"]):
                    findings.append(Finding(
                        type=FindingType.SECRET, url=url,
                        value=f"Base64: {decoded[:60]}...",
                        source="js_base64_secret", severity=Severity.HIGH,
                        context=f"Encoded: {encoded[:50]}...",
                        metadata={"decoded": decoded[:100]},
                    ))
            except Exception:
                pass

        # Dangerous functions
        dangerous = [
            (r"""eval\s*\(""", "eval() call", Severity.HIGH),
            (r"""Function\s*\(""", "Function constructor", Severity.HIGH),
            (r"""document\.write\s*\(""", "document.write()", Severity.MEDIUM),
            (r"""innerHTML\s*=""", "innerHTML assignment", Severity.LOW),
            (r"""postMessage\s*\(""", "postMessage (check origin)", Severity.LOW),
        ]
        for pattern, desc, sev in dangerous:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    type=FindingType.INFO, url=url, value=desc,
                    source="js_analysis", severity=sev,
                    context=f"Found {desc} in inline script",
                ))
    return findings


# ── Subdomain hints ─────────────────────────────────────────────────────────

def find_subdomain_hints(html: str, url: str) -> list[Finding]:
    findings = []
    seen = set()
    parsed = urlparse(url)
    base_domain = parsed.netloc

    domain_pattern = re.compile(r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}')
    skip_domains = [
        "googleapis.com", "gstatic.com", "google.com", "google-analytics.com",
        "googletagmanager.com", "facebook.com", "facebook.net",
        "twitter.com", "youtube.com", "ytimg.com",
        "cloudflare.com", "amazonaws.com", "cloudfront.net",
        "github.com", "github.io", "githubassets.com",
        "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
        "w3.org", "schema.org", "sentry.io", "newrelic.com",
        "fonts.googleapis.com", "fonts.gstatic.com",
    ]
    for match in domain_pattern.finditer(html):
        hostname = match.group(0).split("//")[1].split("/")[0].split("?")[0]
        if any(skip in hostname for skip in skip_domains):
            continue
        target_base = base_domain.split(".")[-2] if "." in base_domain else base_domain
        if target_base in hostname and hostname != base_domain:
            if hostname not in seen:
                seen.add(hostname)
                findings.append(Finding(
                    type=FindingType.SUBDOMAIN, url=url, value=hostname,
                    source="html_subdomain", severity=Severity.INFO,
                    context=f"Subdomain: {match.group(0)[:80]}",
                ))
    return findings


# ── Technology-specific vulnerability hints ──────────────────────────────────

def tech_vulnerability_hints(tech_stack: list[dict], url: str) -> list[Finding]:
    """Generate actionable hints based on detected technology."""
    findings = []
    tech_names = {t["name"].lower(): t for t in tech_stack}

    # WordPress hints
    if "wordpress" in tech_names:
        wp = tech_names["wordpress"]
        version = wp.get("version", "")
        hints = [
            ("WP REST API user enumeration: /wp-json/wp/v2/users", Severity.MEDIUM),
            ("XML-RPC brute force: /xmlrpc.php", Severity.LOW),
            ("WP-Cron abuse: /wp-cron.php", Severity.LOW),
            ("Readme exploit: /readme.html", Severity.LOW),
            ("License.txt: /license.txt", Severity.LOW),
        ]
        for hint, sev in hints:
            findings.append(Finding(
                type=FindingType.INFO, url=url, value=f"WordPress: {hint}",
                source="tech_hint", severity=sev,
                context=f"Based on detected WordPress {version}",
            ))
        if version:
            findings.append(Finding(
                type=FindingType.INFO, url=url,
                value=f"Check CVEs for WordPress {version}",
                source="tech_hint", severity=Severity.MEDIUM,
                context=f"Search: 'WordPress {version} CVE'",
                metadata={"hint_type": "cve_check", "version": version},
            ))

    # jQuery hints
    if "jquery" in tech_names:
        findings.append(Finding(
            type=FindingType.INFO, url=url,
            value="jQuery: Check for XSS in older versions (CVE-2020-11022, CVE-2020-11023)",
            source="tech_hint", severity=Severity.LOW,
            context="jQuery XSS vulnerabilities in versions < 3.5.0",
        ))

    # Nginx hints
    if "nginx" in tech_names:
        findings.append(Finding(
            type=FindingType.INFO, url=url,
            value="Nginx: Check for path traversal (CVE-2021-23017), alias traversal",
            source="tech_hint", severity=Severity.LOW,
            context="Test: /..%2f..%2fetc/passwd",
        ))

    # React/Vue/Angular hints
    framework_hints = {
        "react": "React: Check for __NEXT_DATA__, source maps, prototype pollution",
        "vue.js": "Vue: Check for __vue__, Vue DevTools in prod, template injection",
        "angular": "Angular: Check for ng-version, Angular DevTools, template injection",
    }
    for fw, hint in framework_hints.items():
        if fw in tech_names:
            findings.append(Finding(
                type=FindingType.INFO, url=url, value=hint,
                source="tech_hint", severity=Severity.LOW,
            ))

    return findings


# ── GraphQL detection ────────────────────────────────────────────────────────

def detect_graphql(html: str, url: str) -> list[Finding]:
    findings = []
    graphql_patterns = [
        (r'graphql', "GraphQL endpoint reference"),
        (r'graphiql', "GraphiQL IDE (introspection enabled)"),
        (r'__schema', "GraphQL introspection query"),
        (r'query\s*\{', "GraphQL query"),
        (r'mutation\s*\{', "GraphQL mutation"),
    ]
    for pattern, desc in graphql_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append(Finding(
                type=FindingType.API_ROUTE, url=url,
                value=f"GraphQL: {desc}",
                source="graphql_detection", severity=Severity.MEDIUM,
                context=f"Pattern: {pattern}",
            ))
            break
    return findings


# ── Comment/HTML analysis ───────────────────────────────────────────────────

def analyze_html_comments(html: str, url: str) -> list[Finding]:
    """Find interesting HTML comments with hidden info."""
    findings = []
    comment_pattern = re.compile(r'<!--([\s\S]*?)-->')
    interesting_keywords = [
        "todo", "fixme", "hack", "bug", "password", "secret", "token",
        "api", "key", "admin", "debug", "test", "internal", "staging",
        "deprecated", "remove", "delete", "temp", "temporary",
    ]
    for match in comment_pattern.finditer(html):
        comment = match.group(1).strip()
        if len(comment) < 5:
            continue
        comment_lower = comment.lower()
        if any(kw in comment_lower for kw in interesting_keywords):
            findings.append(Finding(
                type=FindingType.INFO, url=url,
                value=f"HTML comment: {comment[:100]}",
                source="html_comment", severity=Severity.LOW,
                context=f"Interesting comment found in HTML",
                metadata={"comment": comment[:200]},
            ))
    return findings


# ── JWT detection and analysis ───────────────────────────────────────────────

def analyze_jwts(html: str, url: str) -> list[Finding]:
    """Detect and analyze JWT tokens."""
    findings = []
    jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
    for match in jwt_pattern.finditer(html):
        token = match.group(0)
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            # Decode header
            header_pad = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_pad))

            # Decode payload
            payload_pad = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_pad))

            alg = header.get("alg", "unknown")
            exp = payload.get("exp")
            iss = payload.get("iss", "")
            sub = payload.get("sub", "")

            findings.append(Finding(
                type=FindingType.SECRET, url=url,
                value=f"JWT (alg={alg}, iss={iss}, sub={sub})",
                source="jwt_analysis", severity=Severity.MEDIUM,
                context=f"Token: {token[:50]}...",
                metadata={
                    "algorithm": alg,
                    "issuer": iss,
                    "subject": sub,
                    "expired": exp is not None and exp < 0,
                    "token": token[:100],
                },
            ))

            # JWT-specific checks
            if alg == "none":
                findings.append(Finding(
                    type=FindingType.SECRET, url=url,
                    value="JWT with alg=none — signature bypass possible",
                    source="jwt_vulnerability", severity=Severity.CRITICAL,
                    context="Token accepts unsigned JWTs",
                ))
            elif alg in ("HS256", "HS384", "HS512"):
                findings.append(Finding(
                    type=FindingType.INFO, url=url,
                    value=f"JWT uses HMAC ({alg}) — test with common secrets",
                    source="jwt_hint", severity=Severity.LOW,
                    context="Try: secret, password, 123456, etc.",
                ))
        except Exception:
            pass
    return findings


# ── Hidden form analysis ────────────────────────────────────────────────────

def analyze_hidden_forms(html: str, url: str) -> list[Finding]:
    """Analyze hidden forms and interesting form configurations."""
    findings = []

    # Forms with file upload
    if 'type="file"' in html.lower() or "type='file'" in html.lower():
        findings.append(Finding(
            type=FindingType.PARAMETER, url=url,
            value="File upload form detected",
            source="file_upload", severity=Severity.MEDIUM,
            context="Test for: unrestricted file upload, path traversal, polyglots",
        ))

    # Forms with CSRF tokens
    csrf_patterns = [
        r'name=["\']csrf', r'name=["\']_token', r'name=["\']csrf_token',
        r'name=["\']authenticity_token', r'name=["\']__RequestVerificationToken',
    ]
    for pattern in csrf_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append(Finding(
                type=FindingType.PARAMETER, url=url,
                value="CSRF token present",
                source="csrf_token", severity=Severity.INFO,
                context="CSRF protection detected — test token validation",
            ))
            break

    # Multiple forms (interesting for testing)
    form_count = html.lower().count("<form")
    if form_count > 3:
        findings.append(Finding(
            type=FindingType.INFO, url=url,
            value=f"{form_count} forms detected — test each endpoint",
            source="form_analysis", severity=Severity.LOW,
        ))

    return findings
