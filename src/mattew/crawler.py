"""Core crawler — fetches pages, runs all extractors, performs security analysis."""

import asyncio
import logging
import time
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser

import aiohttp

from .models import CrawlResult, FindingType, Severity
from .extractors import (
    extract_endpoints,
    extract_javascript,
    extract_api_routes,
    extract_parameters,
    extract_secrets,
)
from .extractors.fingerprint import fingerprint, check_wordpress_extras
from .extractors.security import (
    find_sensitive_files,
    detect_waf,
    find_source_maps,
    analyze_robots_txt,
)
from .extractors.attack_surface import (
    check_directory_listing,
    find_backup_files,
    find_debug_endpoints,
    find_open_redirects,
    analyze_interesting_headers,
    hunt_js_secrets,
    find_subdomain_hints,
    tech_vulnerability_hints,
    detect_graphql,
    analyze_html_comments,
    analyze_jwts,
    analyze_hidden_forms,
)

logger = logging.getLogger("mattew")

DEFAULT_CONFIG = {
    "max_depth": 3,
    "max_pages": 100,
    "timeout": 15,
    "concurrency": 10,
    "user_agent": "mattew/0.1 (security-research)",
    "follow_external": False,
    "delay": 0.0,
    "check_robots": True,
    "check_sitemap": True,
}


class LinkExtractor(HTMLParser):
    """Extract links from HTML for BFS crawling."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self._skip_tags = {"script", "style", "noscript"}

    def handle_starttag(self, tag, attrs):
        if tag in self._skip_tags:
            return
        for name, value in attrs:
            if name in ("href", "src") and value:
                self.links.append(value)


class Crawler:
    def __init__(self, target: str, config: dict | None = None):
        self.target = target.rstrip("/")
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.result = CrawlResult(target=self.target)
        self._visited: set[str] = set()
        self._queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        self._semaphore: asyncio.Semaphore | None = None
        self._fingerprint_done = False

    async def crawl(self) -> CrawlResult:
        """Run the crawler and return findings."""
        start = time.monotonic()
        parsed = urlparse(self.target)
        base_domain = parsed.netloc

        await self._queue.put((self.target, 0))
        self._semaphore = asyncio.Semaphore(self.config["concurrency"])

        headers = {
            "User-Agent": self.config["user_agent"],
            "Accept-Encoding": "gzip, deflate",
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config["timeout"]),
            headers=headers,
        ) as session:
            # Pre-scan: robots.txt and sitemap.xml
            if self.config.get("check_robots"):
                await self._fetch_robots_txt(session)
            if self.config.get("check_sitemap"):
                await self._fetch_sitemap(session)

            # Main crawl
            tasks = []
            while not self._queue.empty() or tasks:
                done = [t for t in tasks if t.done()]
                for t in done:
                    tasks.remove(t)

                if self._queue.empty():
                    await asyncio.sleep(0.1)
                    continue

                url, depth = await self._queue.get()

                if url in self._visited:
                    continue
                if len(self._visited) >= self.config["max_pages"]:
                    break
                if depth > self.config["max_depth"]:
                    continue

                self._visited.add(url)
                self.result.urls_visited.add(url)

                task = asyncio.create_task(self._fetch_and_analyze(session, url, depth, base_domain))
                tasks.append(task)

                # Polite delay
                if self.config["delay"] > 0:
                    await asyncio.sleep(self.config["delay"])

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        # Remove duplicate findings
        self.result.deduplicate()

        self.result.scan_time = time.monotonic() - start
        return self.result

    async def _fetch_robots_txt(self, session: aiohttp.ClientSession):
        """Fetch and analyze robots.txt."""
        robots_url = urljoin(self.target, "/robots.txt")
        try:
            async with session.get(robots_url, ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    self.result.urls_visited.add(robots_url)
                    findings = analyze_robots_txt(content, self.target)
                    self.result.findings.extend(findings)
                    logger.debug(f"robots.txt: {len(findings)} findings")

                    # Follow sitemaps referenced in robots.txt
                    import re
                    sitemap_urls = re.findall(r'Sitemap:\s*(\S+)', content, re.IGNORECASE)
                    for sitemap_url in sitemap_urls[:5]:
                        await self._fetch_sitemap_content(session, sitemap_url)
        except Exception as e:
            logger.debug(f"robots.txt fetch failed: {e}")

    async def _fetch_sitemap(self, session: aiohttp.ClientSession):
        """Fetch and parse sitemap.xml."""
        sitemap_url = urljoin(self.target, "/sitemap.xml")
        await self._fetch_sitemap_content(session, sitemap_url)

    async def _fetch_sitemap_content(self, session: aiohttp.ClientSession, sitemap_url: str):
        """Parse a sitemap XML and extract URLs."""
        try:
            async with session.get(sitemap_url, ssl=False) as resp:
                if resp.status != 200:
                    return
                content = await resp.text()
                self.result.urls_visited.add(sitemap_url)

                # Simple XML URL extraction
                import re
                from .models import Finding
                urls = re.findall(r'<loc>\s*(.*?)\s*</loc>', content)
                queued = 0
                for url in urls[:200]:
                    parsed = urlparse(url)
                    if parsed.netloc == urlparse(self.target).netloc:
                        if url not in self._visited and len(self._visited) < self.config["max_pages"]:
                            await self._queue.put((url, 1))
                            queued += 1

                if queued:
                    self.result.findings.append(Finding(
                        type=FindingType.ENDPOINT,
                        url=sitemap_url,
                        value=f"{queued} URLs from sitemap",
                        source="sitemap",
                        severity=Severity.INFO,
                        context=f"Parsed {len(urls)} URLs, queued {queued} for crawling",
                    ))

                logger.debug(f"sitemap: found {len(urls)} URLs, queued {queued}")
        except Exception as e:
            logger.debug(f"sitemap fetch failed: {e}")

    async def _fetch_and_analyze(
        self, session: aiohttp.ClientSession, url: str, depth: int, base_domain: str
    ):
        async with self._semaphore:
            html_content = ""
            resp_headers = {}
            try:
                async with session.get(url, ssl=False) as resp:
                    if resp.status != 200:
                        return
                    content_type = resp.headers.get("content-type", "")
                    if "text/html" not in content_type and "javascript" not in content_type:
                        return
                    html_content = await resp.text()
                    resp_headers = dict(resp.headers)
            except Exception as e:
                self.result.errors.append(f"{url}: {e}")
                return

        # ── First page: fingerprinting + security analysis ───────────────
        is_first_page = not self._fingerprint_done
        if is_first_page:
            self._fingerprint_done = True

            # Technology fingerprinting
            techs, tech_findings = fingerprint(html_content, resp_headers, url)
            self.result.findings.extend(tech_findings)
            self.result.tech_stack = [
                {"name": t.name, "category": t.category, "version": t.version}
                for t in techs
            ]

            # WordPress deep checks
            if any(t.name == "WordPress" for t in techs):
                wp_findings = check_wordpress_extras(html_content, url)
                self.result.findings.extend(wp_findings)

            # WAF detection
            waf_findings = detect_waf(resp_headers, html_content)
            self.result.findings.extend(waf_findings)

        # ── Header analysis (every page for diverse findings) ────────────
        header_findings = analyze_interesting_headers(resp_headers, url)
        self.result.findings.extend(header_findings)

        # ── Content extractors (all pages) ───────────────────────────────
        for extractor in [
            extract_endpoints,
            extract_javascript,
            extract_api_routes,
            extract_parameters,
            extract_secrets,
        ]:
            try:
                findings = extractor(html_content, url)
                self.result.findings.extend(findings)
            except Exception as e:
                self.result.errors.append(f"{url}:{extractor.__name__}: {e}")

        # ── Attack surface analysis ──────────────────────────────────────
        attack_extractors = [
            check_directory_listing,
            find_backup_files,
            find_debug_endpoints,
            find_open_redirects,
            hunt_js_secrets,
            find_subdomain_hints,
            detect_graphql,
            analyze_html_comments,
            analyze_jwts,
            analyze_hidden_forms,
        ]
        for extractor in attack_extractors:
            try:
                findings = extractor(html_content, url)
                self.result.findings.extend(findings)
            except Exception as e:
                self.result.errors.append(f"{url}:{extractor.__name__}: {e}")

        # Tech vulnerability hints (first page only)
        if is_first_page and self.result.tech_stack:
            try:
                hints = tech_vulnerability_hints(self.result.tech_stack, url)
                self.result.findings.extend(hints)
            except Exception as e:
                self.result.errors.append(f"{url}:tech_vulnerability_hints: {e}")

        # Sensitive file detection
        try:
            file_findings = find_sensitive_files(html_content, url)
            self.result.findings.extend(file_findings)
        except Exception as e:
            self.result.errors.append(f"{url}:find_sensitive_files: {e}")

        # Source map discovery
        try:
            map_findings = find_source_maps(html_content, url)
            self.result.findings.extend(map_findings)
        except Exception as e:
            self.result.errors.append(f"{url}:find_source_maps: {e}")

        # ── Link extraction for BFS ─────────────────────────────────────
        if depth < self.config["max_depth"]:
            link_extractor = LinkExtractor()
            try:
                link_extractor.feed(html_content)
            except Exception:
                pass

            for link in link_extractor.links:
                full_url = urljoin(url, link)
                parsed = urlparse(full_url)

                if parsed.scheme not in ("http", "https"):
                    continue

                full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    full_url += f"?{parsed.query}"

                if not self.config["follow_external"] and parsed.netloc != base_domain:
                    continue

                if full_url not in self._visited:
                    await self._queue.put((full_url, depth + 1))
