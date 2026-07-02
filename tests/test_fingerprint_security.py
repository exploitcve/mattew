"""Tests for fingerprint and security extractors."""

from mattew.extractors.fingerprint import (
    fingerprint,
    check_wordpress_extras,
    _extract_version,
)
from mattew.extractors.security import (
    check_security_headers,
    check_cors,
    check_cookies,
    find_sensitive_files,
    detect_waf,
    find_source_maps,
    analyze_robots_txt,
    analyze_csp,
)


class TestFingerprint:
    def test_detects_wordpress(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/style.css">'
        techs, findings = fingerprint(html, {}, "https://example.com")
        names = [t.name for t in techs]
        assert "WordPress" in names

    def test_detects_react(self):
        html = '<div data-reactroot><script>React.createElement("div")</script></div>'
        techs, findings = fingerprint(html, {}, "https://example.com")
        names = [t.name for t in techs]
        assert "React" in names

    def test_detects_nginx(self):
        headers = {"Server": "nginx/1.24.0"}
        techs, findings = fingerprint("", headers, "https://example.com")
        names = [t.name for t in techs]
        assert "Nginx" in names

    def test_detects_google_analytics(self):
        html = '<script src="https://www.google-analytics.com/analytics.js"></script>'
        techs, findings = fingerprint(html, {}, "https://example.com")
        names = [t.name for t in techs]
        assert "Google Analytics" in names

    def test_no_false_positives(self):
        html = '<p>This is a normal page with no framework indicators.</p>'
        techs, findings = fingerprint(html, {}, "https://example.com")
        # Should not detect React/Ember/Vue from random text
        names = [t.name for t in techs]
        assert "React" not in names
        assert "Ember.js" not in names
        assert "Vue.js" not in names

    def test_wordpress_version_extracted(self):
        html = '<meta name="generator" content="WordPress 6.4.2">'
        techs, findings = fingerprint(html, {}, "https://example.com")
        wp = [t for t in techs if t.name == "WordPress"]
        assert len(wp) == 1
        assert wp[0].version == "6.4.2"


class TestVersionExtraction:
    def test_wordpress_version(self):
        assert _extract_version("WordPress 6.4.2", "WordPress") == "6.4.2"

    def test_nginx_version(self):
        assert _extract_version("nginx/1.24.0", "Nginx") == "1.24.0"

    def test_no_version(self):
        assert _extract_version("just some text", "WordPress") == ""


class TestWordPressExtras:
    def test_detects_plugins(self):
        html = '<script src="/wp-content/plugins/gravityforms/js/form.js"></script>'
        findings = check_wordpress_extras(html, "https://example.com")
        assert any("gravityforms" in f.value for f in findings)

    def test_detects_theme(self):
        html = '<link href="/wp-content/themes/flavor/style.css">'
        findings = check_wordpress_extras(html, "https://example.com")
        assert any("flavor" in f.value for f in findings)

    def test_detects_xmlrpc(self):
        html = '<link rel="pingback" href="https://example.com/xmlrpc.php">'
        findings = check_wordpress_extras(html, "https://example.com")
        assert any("xmlrpc" in f.value for f in findings)

    def test_detects_rest_api(self):
        html = '<script>fetch("/wp-json/wp/v2/posts")</script>'
        findings = check_wordpress_extras(html, "https://example.com")
        assert any("wp-json" in f.value for f in findings)


class TestSecurityHeaders:
    def test_missing_headers(self):
        findings = check_security_headers({}, "https://example.com")
        header_names = [f.value for f in findings]
        assert "strict-transport-security" in header_names
        assert "content-security-policy" in header_names
        assert "x-content-type-options" in header_names

    def test_present_headers(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        }
        findings = check_security_headers(headers, "https://example.com")
        header_names = [f.value for f in findings]
        assert "strict-transport-security" not in header_names
        assert "content-security-policy" not in header_names
        assert "x-content-type-options" not in header_names

    def test_weak_hsts(self):
        headers = {"Strict-Transport-Security": "max-age=0"}
        findings = check_security_headers(headers, "https://example.com")
        assert any("max-age is 0" in f.context for f in findings)


class TestCORS:
    def test_wildcard_cors(self):
        headers = {"Access-Control-Allow-Origin": "*"}
        findings = check_cors(headers, "https://example.com")
        assert any("wildcard" in f.context for f in findings)

    def test_credentials_cors(self):
        headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        }
        findings = check_cors(headers, "https://example.com")
        assert any("credentials" in f.context for f in findings)


class TestCookies:
    def test_insecure_cookie(self):
        headers = {"Set-Cookie": "session_id=abc123; Path=/"}
        findings = check_cookies(headers, "https://example.com")
        assert len(findings) > 0
        assert any("Secure" in str(f.metadata.get("issues", [])) for f in findings)

    def test_secure_cookie(self):
        headers = {"Set-Cookie": "session_id=abc123; Secure; HttpOnly; SameSite=Strict"}
        findings = check_cookies(headers, "https://example.com")
        assert len(findings) == 0


class TestSensitiveFiles:
    def test_env_reference(self):
        html = '<script>const key = process.env.API_KEY</script>'
        findings = find_sensitive_files(html, "https://example.com")
        assert any("API_KEY" in f.value for f in findings)

    def test_git_reference(self):
        html = '<a href="/.git/config">Git config</a>'
        findings = find_sensitive_files(html, "https://example.com")
        assert any(".git/config" in f.value for f in findings)


class TestWAFDetection:
    def test_cloudflare(self):
        headers = {"Server": "cloudflare"}
        findings = detect_waf(headers, "")
        assert any("Cloudflare" in f.value for f in findings)

    def test_sucuri(self):
        headers = {"X-Sucuri-ID": "12345"}
        findings = detect_waf(headers, "")
        assert any("Sucuri" in f.value for f in findings)


class TestSourceMaps:
    def test_source_mapping_url(self):
        html = '//# sourceMappingURL=app.js.map'
        findings = find_source_maps(html, "https://example.com")
        assert len(findings) == 1
        assert "app.js.map" in findings[0].value


class TestRobotsTxt:
    def test_disallowed_paths(self):
        content = "User-agent: *\nDisallow: /admin/\nDisallow: /private/"
        findings = analyze_robots_txt(content, "https://example.com")
        paths = [f.value for f in findings]
        assert any("/admin/" in p for p in paths)
        assert any("/private/" in p for p in paths)

    def test_sitemap_reference(self):
        content = "Sitemap: https://example.com/sitemap.xml"
        findings = analyze_robots_txt(content, "https://example.com")
        assert any("sitemap.xml" in f.value for f in findings)


class TestCSPAnalysis:
    def test_unsafe_inline(self):
        findings = analyze_csp("default-src 'self' 'unsafe-inline'", "https://example.com")
        assert any("unsafe-inline" in f.value for f in findings)

    def test_unsafe_eval(self):
        findings = analyze_csp("script-src 'self' 'unsafe-eval'", "https://example.com")
        assert any("unsafe-eval" in f.value for f in findings)

    def test_strict_csp(self):
        findings = analyze_csp("default-src 'self'; script-src 'self'", "https://example.com")
        # Should only find missing base-uri
        assert len(findings) == 1
        assert "base-uri" in findings[0].value
