"""CLI entry point for mattew — professional UI with Rich."""

import argparse
import asyncio
import sys
import time

from . import __version__


BANNER = r"""
[bold cyan]

███╗░░░███╗░█████╗░████████╗████████╗███████╗░██╗░░░░░░░██╗
████╗░████║██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝░██║░░██╗░░██║
██╔████╔██║███████║░░░██║░░░░░░██║░░░█████╗░░░╚██╗████╗██╔╝
██║╚██╔╝██║██╔══██║░░░██║░░░░░░██║░░░██╔══╝░░░░████╔═████║░
██║░╚═╝░██║██║░░██║░░░██║░░░░░░██║░░░███████╗░░╚██╔╝░╚██╔╝░
╚═╝░░░░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░░░░╚═╝░░░╚══════╝░░░╚═╝░░░╚═╝░░[/]
[dim]  v{version} — web surface mapper for bug bounty[/]
"""


def _print_banner():
    from rich.console import Console
    console = Console()
    console.print(BANNER.format(version=__version__))


def _print_result(result):
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich import box

    console = Console()
    summary = result.summary()
    security = result.security_score()

    # ── Header panel ─────────────────────────────────────────────────────
    score_color = (
        "green" if security["score"] >= 85 else
        "yellow" if security["score"] >= 70 else
        "red"
    )

    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold cyan", width=12)
    header.add_column()
    header.add_row("Target", summary["target"])
    header.add_row("Pages", str(summary["urls_visited"]))
    header.add_row("Findings", str(summary["total_findings"]))
    header.add_row("Scan time", f"{summary['scan_time']}s")
    header.add_row("Security", f"[bold {score_color}]{security['score']}/100 ({security['rating']})[/]")
    console.print(Panel(header, title="[bold]Scan Results[/]", border_style="cyan", box=box.ROUNDED))

    # ── Tech stack ───────────────────────────────────────────────────────
    if result.tech_stack:
        tech_items = []
        for t in result.tech_stack:
            cat_colors = {
                "cms": "green", "framework": "magenta", "server": "cyan",
                "library": "yellow", "analytics": "blue", "cdn": "bright_black",
            }
            color = cat_colors.get(t["category"], "white")
            ver = f" [dim]{t['version']}[/]" if t.get("version") else ""
            tech_items.append(f"[{color}]{t['name']}[/{color}]{ver} [dim]({t['category']})[/]")
        console.print(Panel(
            "  ".join(tech_items),
            title="[bold]Technology Stack[/]",
            border_style="magenta",
            box=box.ROUNDED,
        ))

    # ── Findings summary ─────────────────────────────────────────────────
    sev_colors = {
        "critical": "bold red", "high": "bold red", "medium": "yellow",
        "low": "blue", "info": "bright_black",
    }

    summary_table = Table(show_header=True, box=box.SIMPLE_HEAVY, padding=(0, 1))
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    summary_table.add_column("Type Breakdown", style="dim")

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = summary["by_severity"].get(sev, 0)
        if count == 0:
            continue
        # Build type breakdown for this severity
        type_breakdown = {}
        for f in result.findings:
            if f.severity.value == sev:
                type_breakdown[f.type.value] = type_breakdown.get(f.type.value, 0) + 1
        breakdown_str = ", ".join(f"{k}:{v}" for k, v in sorted(type_breakdown.items()))

        summary_table.add_row(
            f"[{sev_colors.get(sev, 'white')}]{sev.upper()}[/]",
            str(count),
            breakdown_str,
        )

    console.print(Panel(summary_table, title="[bold]Findings by Severity[/]", border_style="blue", box=box.ROUNDED))

    # ── Security issues (if any) ─────────────────────────────────────────
    security_findings = [f for f in result.findings if f.severity.value in ("critical", "high", "medium")]
    if security_findings:
        sec_table = Table(show_header=True, box=box.ROUNDED, padding=(0, 1))
        sec_table.add_column("Sev", width=4, style="bold")
        sec_table.add_column("Type", width=12)
        sec_table.add_column("Value", max_width=50)
        sec_table.add_column("Context", max_width=40, style="dim")

        for f in sorted(security_findings, key=lambda x: ["critical", "high", "medium"].index(x.severity.value))[:25]:
            sev_style = sev_colors.get(f.severity.value, "white")
            sev_label = f.severity.value[0].upper()
            sec_table.add_row(
                f"[{sev_style}]{sev_label}[/]",
                f.type.value,
                f.value[:50],
                f.context[:40] if f.context else "",
            )
        console.print(Panel(sec_table, title="[bold]Security Issues[/]", border_style="red", box=box.ROUNDED))

    # ── Errors ───────────────────────────────────────────────────────────
    if result.errors:
        err_text = "\n".join(f"  [red]×[/] {e}" for e in result.errors[:10])
        console.print(Panel(err_text, title="[bold red]Errors[/]", border_style="red", box=box.ROUNDED))

    # ── Footer ───────────────────────────────────────────────────────────
    console.print(
        f"\n[dim]mattew v{__version__} — "
        f"report generated at {time.strftime('%Y-%m-%d %H:%M:%S')} UTC[/]\n"
    )


def main():
    parser = argparse.ArgumentParser(
        prog="mattew",
        description="Web application surface mapper for security research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  mattew https://example.com                        Basic scan
  mattew https://example.com -d 5 -p 200            Deep scan
  mattew https://example.com -f html -o report.html  HTML report
  mattew https://example.com -f json -o results.json JSON output
  mattew https://example.com --delay 1               Polite crawling
        """,
    )
    parser.add_argument("target", help="Target URL to crawl")
    parser.add_argument("-d", "--depth", type=int, default=3, help="Max crawl depth (default: 3)")
    parser.add_argument("-p", "--max-pages", type=int, default=100, help="Max pages to scan (default: 100)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Max concurrent requests (default: 10)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["text", "json", "markdown", "md", "html"], default="text", help="Output format (default: text)")
    parser.add_argument("--follow-external", action="store_true", help="Follow links to external domains")
    parser.add_argument("--user-agent", default="mattew/0.1 (security-research)", help="Custom User-Agent string")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds")
    parser.add_argument("--no-robots", action="store_true", help="Skip robots.txt analysis")
    parser.add_argument("--no-sitemap", action="store_true", help="Skip sitemap.xml parsing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Setup logging
    import logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    # Validate target
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    config = {
        "max_depth": args.depth,
        "max_pages": args.max_pages,
        "concurrency": args.concurrency,
        "timeout": args.timeout,
        "follow_external": args.follow_external,
        "user_agent": args.user_agent,
        "delay": args.delay,
        "check_robots": not args.no_robots,
        "check_sitemap": not args.no_sitemap,
    }

    # ── Banner ───────────────────────────────────────────────────────────
    # Only show banner for terminal text output
    is_terminal = sys.stdout.isatty()
    show_banner = is_terminal and args.format == "text" and not args.output

    if show_banner:
        _print_banner()

    # ── Crawl ────────────────────────────────────────────────────────────
    from .crawler import Crawler
    from .output import output

    crawler = Crawler(target, config)

    if args.format == "text" and not args.output:
        # Show rich progress for terminal text output
        from rich.status import Status
        with Status(f"[bold cyan]Scanning {target}...", spinner="dots") as status:
            result = asyncio.run(crawler.crawl())
        _print_result(result)
    else:
        # File output or non-text format
        if is_terminal and not args.output:
            from rich.console import Console
            Console().print(f"[cyan]Scanning {target}...[/]", end="")
        result = asyncio.run(crawler.crawl())
        if is_terminal and not args.output:
            from rich.console import Console
            Console().print(f" [green]done[/] ({result.summary()['total_findings']} findings)")
        output(result, fmt=args.format, file=args.output)
        if args.output and is_terminal:
            from rich.console import Console
            Console().print(f"[green]✓[/] Report saved to {args.output}")


if __name__ == "__main__":
    main()
