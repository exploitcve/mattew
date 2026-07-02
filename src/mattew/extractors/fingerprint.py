"""Technology fingerprinter — identifies frameworks, CMS, servers, and libraries."""

import re
from dataclasses import dataclass, field

from ..models import Finding, FindingType, Severity


@dataclass
class TechFingerprint:
    name: str
    category: str  # cms, framework, language, server, library, analytics, cdn
    version: str = ""
    confidence: float = 1.0
    evidence: str = ""


# ── Signature databases ──────────────────────────────────────────────────────

CMS_SIGNATURES = [
    (r"wp-content/", "WordPress", "cms"),
    (r"wp-includes/", "WordPress", "cms"),
    (r'content="WordPress', "WordPress", "cms"),
    (r'/sites/default/files/', "Drupal", "cms"),
    (r'content="Drupal', "Drupal", "cms"),
    (r"Joomla!", "Joomla", "cms"),
    (r"/typo3/", "TYPO3", "cms"),
    (r"cdn\.shopify\.com|Shopify\.theme|myshopify\.com", "Shopify", "cms"),
    (r"squarespace\.com|static\.squarespace\.com", "Squarespace", "cms"),
    (r"static\.wixstatic\.com|wix\.com", "Wix", "cms"),
    (r"assets\.website-files\.com|webflow\.io", "Webflow", "cms"),
    (r"/ghost/", "Ghost", "cms"),
    (r"cdn\.contentful\.com|contentful\.com", "Contentful", "cms"),
    (r"strapi\.io", "Strapi", "cms"),
    (r"payload\.cms", "Payload CMS", "cms"),
    (r"sanity\.io", "Sanity", "cms"),
]

FRAMEWORK_SIGNATURES = [
    (r"__NEXT_DATA__", "Next.js", "framework"),
    (r"_next/static", "Next.js", "framework"),
    (r"__nuxt", "Nuxt.js", "framework"),
    (r"_nuxt/", "Nuxt.js", "framework"),
    (r"ng-version", "Angular", "framework"),
    (r"ng-app", "Angular", "framework"),
    (r"(?:data-reactroot|data-reactid|React\.createElement|react\.production)", "React", "framework"),
    (r"vue\.js|vue\.min\.js|__vue__|data-v-", "Vue.js", "framework"),
    (r"svelte", "Svelte", "framework"),
    (r"(?:Ember\.|ember\.|__ember|data-ember)", "Ember.js", "framework"),
    (r"backbone", "Backbone.js", "framework"),
    (r"angular\.js", "AngularJS", "framework"),
    (r"jquery", "jQuery", "library"),
    (r"bootstrap", "Bootstrap", "library"),
    (r"tailwind", "Tailwind CSS", "library"),
    (r"laravel", "Laravel", "framework"),
    (r"django", "Django", "framework"),
    (r"rails|ruby-on-rails", "Ruby on Rails", "framework"),
    (r"spring", "Spring", "framework"),
    (r"express", "Express.js", "framework"),
    (r"fastapi", "FastAPI", "framework"),
    (r"flask", "Flask", "framework"),
    (r"rails", "Rails", "framework"),
    (r"dotnet|aspnet", "ASP.NET", "framework"),
    (r"gatsby", "Gatsby", "framework"),
    (r"hugo", "Hugo", "framework"),
    (r"jekyll", "Jekyll", "framework"),
]

SERVER_SIGNATURES = [
    (r"server:\s*nginx", "Nginx", "server"),
    (r"server:\s*apache", "Apache", "server"),
    (r"server:\s*cloudflare", "Cloudflare", "server"),
    (r"server:\s*amazonaws", "AWS", "server"),
    (r"server:\s*microsoft-iis", "Microsoft IIS", "server"),
    (r"server:\s*lighttpd", "Lighttpd", "server"),
    (r"server:\s*caddy", "Caddy", "server"),
    (r"x-powered-by:\s*express", "Express.js", "server"),
    (r"x-powered-by:\s*php", "PHP", "language"),
    (r"x-powered-by:\s*asp\.net", "ASP.NET", "server"),
    (r"x-generated-by", "", "server"),
]

ANALYTICS_SIGNATURES = [
    (r"google-analytics\.com|gtag|googletagmanager", "Google Analytics", "analytics"),
    (r"googletagmanager\.com/gtm\.js", "Google Tag Manager", "analytics"),
    (r"facebook\.net/en_US/fbevents", "Facebook Pixel", "analytics"),
    (r"connect\.facebook", "Facebook SDK", "analytics"),
    (r"hotjar\.com", "Hotjar", "analytics"),
    (r"segment\.com/analytics", "Segment", "analytics"),
    (r"mixpanel\.com", "Mixpanel", "analytics"),
    (r"amplitude\.com", "Amplitude", "analytics"),
    (r"plausible\.io", "Plausible", "analytics"),
    (r"umami\.is", "Umami", "analytics"),
    (r"matomo|piwik", "Matomo", "analytics"),
    (r"newrelic", "New Relic", "analytics"),
    (r"sentry\.io|Sentry", "Sentry", "analytics"),
    (r"datadoghq", "Datadog", "analytics"),
]

CDN_SIGNATURES = [
    (r"cloudflare", "Cloudflare", "cdn"),
    (r"amazonaws\.com", "AWS CloudFront", "cdn"),
    (r"akamai", "Akamai", "cdn"),
    (r"fastly", "Fastly", "cdn"),
    (r"stackpath", "StackPath", "cdn"),
    (r"jsdelivr", "jsDelivr", "cdn"),
    (r"unpkg\.com", "unpkg", "cdn"),
    (r"cdnjs\.cloudflare", "cdnjs", "cdn"),
]

VERSION_PATTERNS = [
    (r"WordPress\s+([\d.]+)", "WordPress"),
    (r"Drupal\s+([\d.]+)", "Drupal"),
    (r"jQuery[ /v]+([\d.]+)", "jQuery"),
    (r"bootstrap[/ v]+([\d.]+)", "Bootstrap"),
    (r"Next\.js\s+([\d.]+)", "Next.js"),
    (r"Nuxt\.js\s+([\d.]+)", "Nuxt.js"),
    (r"angular[/\s]+v?([\d.]+)", "Angular"),
    (r"react[/\s]+v?([\d.]+)", "React"),
    (r"vue[/\s]+v?([\d.]+)", "Vue.js"),
    (r"nginx/([\d.]+)", "Nginx"),
    (r"Apache/([\d.]+)", "Apache"),
    (r"PHP/([\d.]+)", "PHP"),
    (r"IIS/([\d.]+)", "IIS"),
]


def _extract_version(text: str, tech_name: str) -> str:
    """Extract version for a specific tech from text."""
    for pattern, name in VERSION_PATTERNS:
        if name.lower() == tech_name.lower():
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return m.group(1)
    return ""


def fingerprint(html: str, headers: dict[str, str], url: str) -> tuple[list[TechFingerprint], list[Finding]]:
    """Analyze HTML and headers, return tech stack + findings."""
    techs: list[TechFingerprint] = []
    findings: list[Finding] = []
    seen: set[str] = set()

    combined = html + "\n".join(f"{k}: {v}" for k, v in headers.items())

    all_sigs = (
        CMS_SIGNATURES + FRAMEWORK_SIGNATURES +
        SERVER_SIGNATURES + ANALYTICS_SIGNATURES + CDN_SIGNATURES
    )

    for pattern, name, category in all_sigs:
        if name and name.lower() in seen:
            continue
        if re.search(pattern, combined, re.IGNORECASE):
            seen.add(name.lower())
            ver = _extract_version(combined, name) if category in ("cms", "framework", "server", "language") else ""
            techs.append(TechFingerprint(
                name=name,
                category=category,
                version=ver,
                evidence=pattern,
            ))
            findings.append(Finding(
                type=FindingType.INFO,
                url=url,
                value=f"{name} {ver}".strip(),
                source=f"fingerprint_{category}",
                severity=Severity.INFO,
                context=f"Detected via pattern: {pattern}",
                metadata={"category": category, "version": ver},
            ))

    return techs, findings


# ── CMS-specific deep checks ────────────────────────────────────────────────

def check_wordpress_extras(html: str, base_url: str) -> list[Finding]:
    """WordPress-specific enumeration: versions, plugins, themes."""
    findings = []

    # Plugin enumeration
    plugin_pattern = re.compile(r'wp-content/plugins/([^/"\s]+)')
    plugins = set(plugin_pattern.findall(html))
    for plugin in plugins:
        findings.append(Finding(
            type=FindingType.ENDPOINT,
            url=base_url,
            value=f"WordPress plugin: {plugin}",
            source="wordpress_plugin_enum",
            severity=Severity.LOW,
            metadata={"plugin": plugin},
        ))

    # Theme enumeration
    theme_pattern = re.compile(r'wp-content/themes/([^/"\s]+)')
    themes = set(theme_pattern.findall(html))
    for theme in themes:
        findings.append(Finding(
            type=FindingType.ENDPOINT,
            url=base_url,
            value=f"WordPress theme: {theme}",
            source="wordpress_theme_enum",
            severity=Severity.INFO,
            metadata={"theme": theme},
        ))

    # WordPress version in generator tag
    gen_pattern = re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']', re.I)
    m = gen_pattern.search(html)
    if m:
        findings.append(Finding(
            type=FindingType.INFO,
            url=base_url,
            value=f"WordPress version: {m.group(1)}",
            source="wordpress_version",
            severity=Severity.MEDIUM,
            metadata={"version": m.group(1)},
        ))

    # XML-RPC
    if "xmlrpc" in html.lower():
        findings.append(Finding(
            type=FindingType.ENDPOINT,
            url=base_url,
            value=f"{base_url}/xmlrpc.php",
            source="wordpress_xmlrpc",
            severity=Severity.MEDIUM,
            context="XML-RPC endpoint referenced in HTML",
        ))

    # WP REST API
    if "wp-json" in html:
        findings.append(Finding(
            type=FindingType.API_ROUTE,
            url=base_url,
            value=f"{base_url}/wp-json/wp/v2/",
            source="wordpress_rest_api",
            severity=Severity.LOW,
            context="WordPress REST API detected",
        ))

    return findings
