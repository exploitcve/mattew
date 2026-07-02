"""Secret extractor — finds hardcoded secrets with minimal false positives."""

import math
import re
from collections import Counter

from ..models import Finding, FindingType, Severity


# ── False positive exclusions ────────────────────────────────────────────────

EXCLUDE_VALUES = {
    "your_api_key_here", "replace_with_your", "xxx", "example", "test",
    "placeholder", "todo", "fixme", "changeme", "default", "sample",
    "null", "undefined", "true", "false", "none", "empty", "blank",
    "0000000000000000", "1111111111111111", "aaaaaaaaaaaaaaaa",
    "false", "true", "0", "1", "yes", "no", "on", "off",
    "password", "secret", "token", "key", "api_key", "auth_token",
    "none", "nil", "na", "n/a", "undefined", "void",
}

EXCLUDE_CONTEXTS = {
    "node_modules", "package.json", "package-lock.json", "yarn.lock",
    "composer.lock", "Gemfile.lock", ".map", "sourceMappingURL",
    "min.js", "min.css", ".bundle.js",
}


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_high_entropy(data: str, min_entropy: float = 4.0) -> bool:
    """Check if string has high entropy (likely random/secret)."""
    if len(data) < 20:
        return False
    return _shannon_entropy(data) >= min_entropy


def _is_excluded(value: str) -> bool:
    """Check if value is a known false positive."""
    lower = value.lower().strip()
    if lower in EXCLUDE_VALUES:
        return True
    if len(lower) < 8:
        return True
    # Common patterns that look like secrets but aren't
    if re.match(r'^[a-f0-9]{8,}$', lower):  # hex hashes
        return True
    if re.match(r'^[0-9]+$', lower):  # pure numbers
        return True
    if re.match(r'^[a-z]+$', lower):  # pure lowercase
        return True
    return False


def _in_excluded_context(html: str, start: int, end: int) -> bool:
    """Check if match is in an excluded context (comments, node_modules, etc.)."""
    # Check surrounding 200 chars
    context_start = max(0, start - 200)
    context = html[context_start:start]
    for excl in EXCLUDE_CONTEXTS:
        if excl in context.lower():
            return True
    # Check if inside HTML comment
    if "<!--" in context and "-->" not in context:
        return True
    return False


# ── Secret patterns with validation ──────────────────────────────────────────

SECRET_PATTERNS = [
    # High-confidence: format-specific tokens
    (r"""ghp_[a-zA-Z0-9]{36}""", "github_pat", Severity.CRITICAL, True),
    (r"""gho_[a-zA-Z0-9]{36}""", "github_oauth", Severity.CRITICAL, True),
    (r"""ghu_[a-zA-Z0-9]{36}""", "github_app", Severity.CRITICAL, True),
    (r"""ghs_[a-zA-Z0-9]{36}""", "github_app_secret", Severity.CRITICAL, True),
    (r"""ghr_[a-zA-Z0-9]{36}""", "github_refresh", Severity.CRITICAL, True),
    (r"""glpat-[a-zA-Z0-9\-]{20,}""", "gitlab_pat", Severity.CRITICAL, True),
    (r"""glptt-[a-zA-Z0-9\-]{20,}""", "gitlab_ptt", Severity.CRITICAL, True),
    (r"""xox[bpsar]-[a-zA-Z0-9-]+""", "slack_token", Severity.HIGH, True),
    (r"""(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,}""", "stripe_key", Severity.CRITICAL, True),
    (r"""AIza[0-9A-Za-z_-]{35}""", "google_api_key", Severity.HIGH, True),
    (r"""eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}""", "jwt_token", Severity.HIGH, False),
    (r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----""", "private_key", Severity.CRITICAL, False),

    # AWS keys (specific format)
    (r"""(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}""", "aws_access_key", Severity.CRITICAL, True),

    # Connection strings (high confidence)
    (r"""(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|smtp)://[^\s'"`<>]{20,}""", "connection_string", Severity.CRITICAL, False),

    # GCP service account key
    (r"""-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----[\s\S]*?"""r"""-----BEGIN PRIVATE KEY-----""", "gcp_service_account", Severity.CRITICAL, True),
]


def extract_secrets(html: str, url: str) -> list[Finding]:
    findings = []
    seen = set()

    for pattern, secret_type, severity, needs_entropy in SECRET_PATTERNS:
        for match in re.finditer(pattern, html):
            # Skip if in excluded context
            if _in_excluded_context(html, match.start(), match.end()):
                continue

            value = match.group(0) if match.lastindex is None else match.group(1)

            # Skip excluded values
            if _is_excluded(value):
                continue

            # Entropy check for non-format-specific patterns
            if needs_entropy and not _is_high_entropy(value, 3.5):
                continue

            # Deduplicate
            dedup_key = f"{secret_type}:{value[:40]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Extract surrounding context for verification
            ctx_start = max(0, match.start() - 50)
            ctx_end = min(len(html), match.end() + 50)
            context = html[ctx_start:ctx_end].replace("\n", " ")[:150]

            findings.append(Finding(
                type=FindingType.SECRET,
                url=url,
                value=value[:120] + ("..." if len(value) > 120 else ""),
                source=f"secret_{secret_type}",
                severity=severity,
                context=context,
                metadata={
                    "secret_type": secret_type,
                    "entropy": round(_shannon_entropy(value), 2),
                    "length": len(value),
                },
            ))

    # ── Context-aware secret detection ───────────────────────────────────
    # Only look for variable-assigned secrets inside <script> tags
    script_pattern = re.compile(r'<script[^>]*>([\s\S]*?)</script>', re.IGNORECASE)
    for script_match in script_pattern.finditer(html):
        script_content = script_match.group(1)
        script_start = script_match.start(1)

        # API keys in variable assignments
        var_pattern = re.compile(
            r"""(?:(?:const|let|var)\s+)?(\w*(?:api[_-]?key|apikey|secret|token|auth|password|credential)\w*)\s*=\s*['"`]([^'"`\s]{20,})['"`]""",
            re.IGNORECASE,
        )
        for var_match in var_pattern.finditer(script_content):
            var_name = var_match.group(1)
            value = var_match.group(2)

            if _is_excluded(value):
                continue
            if not _is_high_entropy(value, 3.5):
                continue

            dedup_key = f"var:{var_name}:{value[:30]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(Finding(
                type=FindingType.SECRET,
                url=url,
                value=f"{var_name} = {value[:80]}...",
                source="script_variable",
                severity=Severity.HIGH,
                context=var_match.group(0)[:120],
                metadata={
                    "secret_type": "script_variable",
                    "variable": var_name,
                    "entropy": round(_shannon_entropy(value), 2),
                },
            ))

    return findings
