"""Output formatting — JSON, text, markdown, and HTML reports."""

import json
import sys
from datetime import datetime, timezone

from .models import CrawlResult


def format_json(result: CrawlResult) -> str:
    data = {
        "meta": {
            "tool": "mattew",
            "version": "0.1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **result.summary(),
            "security_score": result.security_score(),
        },
        "tech_stack": result.tech_stack,
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }
    return json.dumps(data, indent=2)


def format_text(result: CrawlResult) -> str:
    lines = []
    summary = result.summary()
    security = result.security_score()

    lines.append(f"╔══════════════════════════════════════════════╗")
    lines.append(f"║         mattew — Surface Map Report         ║")
    lines.append(f"╚══════════════════════════════════════════════╝")
    lines.append(f"")
    lines.append(f"  Target:      {summary['target']}")
    lines.append(f"  Pages:       {summary['urls_visited']}")
    lines.append(f"  Findings:    {summary['total_findings']}")
    lines.append(f"  Scan time:   {summary['scan_time']}s")
    lines.append(f"  Errors:      {summary['errors']}")
    lines.append(f"")
    lines.append(f"  Security:    {security['score']}/100 ({security['rating']})")
    lines.append(f"")

    # Tech stack
    if result.tech_stack:
        lines.append("── Technology Stack ──")
        for tech in result.tech_stack:
            ver = f" {tech['version']}" if tech.get("version") else ""
            lines.append(f"  [{tech['category']:<10}] {tech['name']}{ver}")
        lines.append("")

    # Findings by type
    lines.append("── Findings by Type ──")
    for ftype, count in sorted(summary["by_type"].items()):
        lines.append(f"  {ftype:<20} {count}")
    lines.append("")

    # Findings by severity
    lines.append("── Findings by Severity ──")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in summary["by_severity"]:
            marker = {"critical": "!!!", "high": " !!", "medium": "  !", "low": "   .", "info": "    "}.get(sev, " ")
            lines.append(f"  {marker} {sev:<12} {summary['by_severity'][sev]}")
    lines.append("")

    # Detailed findings — security issues first
    security_types = {"secret", "header", "waf", "file"}
    other_types = {"endpoint", "javascript", "api_route", "parameter", "info", "tech", "comment", "form", "subdomain"}

    for section_name, type_set in [("Security Issues", security_types), ("Surface Findings", other_types)]:
        section_findings = [f for f in result.findings if f.type.value in type_set]
        if not section_findings:
            continue

        lines.append(f"── {section_name} ({len(section_findings)}) ──")
        for f in section_findings:
            sev_marker = {
                "critical": "!!!",
                "high": " !!",
                "medium": "  !",
                "low": "   .",
                "info": "    ",
            }.get(f.severity.value, "    ")
            lines.append(f"  [{sev_marker}] {f.type.value:<12} {f.value}")
            if f.context:
                lines.append(f"           {f.context[:100]}")
        lines.append("")

    if result.errors:
        lines.append("── Errors ──")
        for err in result.errors:
            lines.append(f"  {err}")

    return "\n".join(lines)


def format_markdown(result: CrawlResult) -> str:
    lines = []
    summary = result.summary()
    security = result.security_score()

    lines.append(f"# mattew — Surface Map Report")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Target | `{summary['target']}` |")
    lines.append(f"| Pages scanned | {summary['urls_visited']} |")
    lines.append(f"| Total findings | {summary['total_findings']} |")
    lines.append(f"| Security score | **{security['score']}/100 ({security['rating']})** |")
    lines.append(f"| Scan time | {summary['scan_time']}s |")
    lines.append(f"| Errors | {summary['errors']} |")
    lines.append(f"")

    # Tech stack
    if result.tech_stack:
        lines.append("## Technology Stack")
        lines.append("")
        lines.append("| Category | Technology | Version |")
        lines.append("|----------|------------|---------|")
        for tech in result.tech_stack:
            lines.append(f"| {tech['category']} | {tech['name']} | {tech.get('version', '-')} |")
        lines.append("")

    # Security issues
    security_findings = [f for f in result.findings if f.severity.value in ("critical", "high", "medium")]
    if security_findings:
        lines.append("## Security Issues")
        lines.append("")
        lines.append("| Severity | Type | Value | Context |")
        lines.append("|----------|------|-------|---------|")
        for f in sorted(security_findings, key=lambda x: ["critical", "high", "medium"].index(x.severity.value)):
            lines.append(f"| {f.severity.value.upper()} | {f.type.value} | `{f.value[:60]}` | {f.context[:60]} |")
        lines.append("")

    # Summary tables
    lines.append("## Findings Summary")
    lines.append("")
    lines.append("### By Type")
    lines.append("")
    lines.append("| Type | Count |")
    lines.append("|------|-------|")
    for ftype, count in sorted(summary["by_type"].items()):
        lines.append(f"| {ftype} | {count} |")
    lines.append("")

    lines.append("### By Severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in summary["by_severity"]:
            lines.append(f"| {sev} | {summary['by_severity'][sev]} |")
    lines.append("")

    return "\n".join(lines)


FORMATTERS = {
    "json": format_json,
    "text": format_text,
    "markdown": format_markdown,
    "md": format_markdown,
}


def output(result: CrawlResult, fmt: str = "text", file: str | None = None):
    if fmt == "html":
        from .html_report import generate_html
        content = generate_html(result)
    else:
        formatter = FORMATTERS.get(fmt, format_text)
        content = formatter(result)

    if file:
        with open(file, "w") as f:
            f.write(content)
    else:
        print(content)
