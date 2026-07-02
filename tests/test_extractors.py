"""Tests for mattew extractors."""

from mattew.extractors import (
    extract_endpoints,
    extract_javascript,
    extract_api_routes,
    extract_parameters,
    extract_secrets,
)


class TestEndpointExtraction:
    def test_extracts_href_links(self):
        html = '<a href="/login">Login</a><a href="/dashboard">Dashboard</a>'
        findings = extract_endpoints(html, "https://example.com")
        urls = {f.value for f in findings}
        assert "https://example.com/login" in urls
        assert "https://example.com/dashboard" in urls

    def test_extracts_fetch_calls(self):
        html = '<script>fetch("/api/users"); fetch("/api/posts")</script>'
        findings = extract_endpoints(html, "https://example.com")
        urls = {f.value for f in findings}
        assert "https://example.com/api/users" in urls
        assert "https://example.com/api/posts" in urls

    def test_skips_javascript_protocols(self):
        html = '<a href="javascript:void(0)">Click</a>'
        findings = extract_endpoints(html, "https://example.com")
        assert len(findings) == 0

    def test_extracts_api_routes(self):
        html = "<script>axios.get('/api/v1/data')</script>"
        findings = extract_endpoints(html, "https://example.com")
        urls = {f.value for f in findings}
        assert "https://example.com/api/v1/data" in urls


class TestJavaScriptExtraction:
    def test_extracts_script_src(self):
        html = '<script src="/static/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
        findings = extract_javascript(html, "https://example.com")
        urls = {f.value for f in findings}
        assert "https://example.com/static/app.js" in urls
        assert "https://cdn.example.com/lib.js" in urls

    def test_extracts_dynamic_imports(self):
        html = "<script>import('./module.js')</script>"
        findings = extract_javascript(html, "https://example.com")
        assert any("module.js" in f.value for f in findings)


class TestSecretExtraction:
    def test_extracts_format_specific_tokens(self):
        html = 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata["secret_type"] == "github_pat" for f in findings)

    def test_extracts_private_keys(self):
        html = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy4AHB7MhgHcLiSPlqF\n-----END RSA PRIVATE KEY-----"
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata["secret_type"] == "private_key" for f in findings)

    def test_extracts_jwt_tokens(self):
        html = 'token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata["secret_type"] == "jwt_token" for f in findings)

    def test_extracts_aws_keys(self):
        html = 'const key = "AKIAIOSFODNN7EXAMPLE"'
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata["secret_type"] == "aws_access_key" for f in findings)

    def test_extracts_stripe_keys(self):
        html = 'const key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"'
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata["secret_type"] == "stripe_key" for f in findings)

    def test_extracts_google_api_keys(self):
        html = 'const key = "AIzaSyDexample1234567890abcdefghijklmnopq"'
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata["secret_type"] == "google_api_key" for f in findings)

    def test_extracts_slack_tokens(self):
        html = 'const token = "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"'
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata["secret_type"] == "slack_token" for f in findings)

    def test_extracts_gitlab_tokens(self):
        html = 'const token = "glpat-ABCDefGhIjKlMnOpQrStUv"'
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata["secret_type"] == "gitlab_pat" for f in findings)

    def test_extracts_connection_strings(self):
        html = 'const db = "postgresql://user:pass@localhost:5432/dbname"'
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata["secret_type"] == "connection_string" for f in findings)

    def test_extracts_script_variables(self):
        html = '<script>const apiKey = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"</script>'
        findings = extract_secrets(html, "https://example.com")
        assert any(f.metadata.get("secret_type") == "script_variable" for f in findings)

    def test_excludes_common_false_positives(self):
        html = 'const apiKey = "placeholder"'
        findings = extract_secrets(html, "https://example.com")
        assert len(findings) == 0

    def test_excludes_hex_hashes(self):
        html = 'const hash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"'
        findings = extract_secrets(html, "https://example.com")
        assert len(findings) == 0


class TestParameterExtraction:
    def test_extracts_form_inputs(self):
        html = '<form><input name="username" type="text"><input name="email" type="email"></form>'
        findings = extract_parameters(html, "https://example.com")
        params = {f.value for f in findings}
        assert "username" in params
        assert "email" in params

    def test_extracts_hidden_inputs(self):
        html = '<input type="hidden" name="custom_token" value="abc123">'
        findings = extract_parameters(html, "https://example.com")
        assert any(f.value == "custom_token" and f.metadata["hidden"] for f in findings)

    def test_extracts_query_params(self):
        html = '<a href="/search?search_term=test&filter=all&sort_by=date">Search</a>'
        findings = extract_parameters(html, "https://example.com")
        params = {f.value for f in findings}
        assert "search_term" in params
        assert "filter" in params
        assert "sort_by" in params

    def test_extracts_file_upload_inputs(self):
        html = '<input type="file" name="document">'
        findings = extract_parameters(html, "https://example.com")
        assert any(f.value == "document" and f.metadata["file_upload"] for f in findings)

    def test_extracts_localstorage_keys(self):
        html = '<script>localStorage.setItem("user_token", "abc123")</script>'
        findings = extract_parameters(html, "https://example.com")
        assert any(f.value == "user_token" and f.source == "browser_storage" for f in findings)

    def test_excludes_utm_params(self):
        html = '<a href="/page?utm_source=google&utm_medium=cpc">Link</a>'
        findings = extract_parameters(html, "https://example.com")
        params = {f.value for f in findings}
        assert "utm_source" not in params
        assert "utm_medium" not in params

    def test_excludes_common_params(self):
        html = '<a href="/page?id=1&page=2&limit=10">Link</a>'
        findings = extract_parameters(html, "https://example.com")
        params = {f.value for f in findings}
        assert "id" not in params
        assert "page" not in params
        assert "limit" not in params


class TestAPIRouteExtraction:
    def test_extracts_graphql(self):
        html = 'fetch("/graphql", {method: "POST"})'
        findings = extract_api_routes(html, "https://example.com")
        assert any("graphql" in f.value for f in findings)

    def test_extracts_websockets(self):
        html = 'const ws = new WebSocket("wss://example.com/ws")'
        findings = extract_api_routes(html, "https://example.com")
        assert any("wss://" in f.value for f in findings)

    def test_extracts_config_urls(self):
        html = 'const API_URL = "https://api.example.com/v2"'
        findings = extract_api_routes(html, "https://example.com")
        assert any("api.example.com" in f.value for f in findings)
