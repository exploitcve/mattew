# mattew

> **Web Application Surface Mapper for Bug Bounty Hunters & Security Researchers**

<img width="3420" height="1736" alt="CleanShot 2026-07-03 at 00 28 30@2x" src="https://github.com/user-attachments/assets/dc4d2938-d832-4f7f-9a11-adacce63f462" />

---

**mattew** crawls target websites, extracts hidden attack surface, runs security analysis, fingerprints technology, and generates professional reports , all in one command.

- Zero false positives
- Professional HTML reports
- Bug bounty ready

---

## What mattew Does

mattew is a web reconnaissance tool that automates the tedious parts of bug bounty hunting. Point it at a target and it will:

### Surface Discovery

| Feature | What It Finds |
|---------|---------------|
| **Endpoints** | Links, forms, actions, href/src attributes |
| **JavaScript** | Script files, dynamic imports, inline analysis |
| **API Routes** | REST, GraphQL, WebSocket, config base URLs |
| **Parameters** | Form inputs, hidden fields, query params, localStorage |
| **Secrets** | API keys, tokens, private keys (format-specific) |
| **Subdomains** | Internal subdomains from HTML references |

### Security Analysis

| Feature | What It Finds |
|---------|---------------|
| **Security Headers** | Missing HSTS, CSP, X-Content-Type-Options, X-Frame-Options |
| **CORS** | Wildcard origins, credential reflection |
| **Cookies** | Missing Secure/HttpOnly/SameSite flags |
| **WAF Detection** | Cloudflare, Sucuri, AWS WAF, ModSecurity |

### Bug Bounty Intelligence

| Feature | What It Finds |
|---------|---------------|
| **Tech Fingerprinting** | CMS, frameworks, servers, libraries, analytics |
| **WordPress Deep Scan** | Plugins, themes, version, REST API, XML-RPC |
| **Debug Endpoints** | /admin, /swagger, /phpinfo, /.env |
| **Directory Listing** | Open Apache/Nginx directories |
| **Backup Files** | .bak, .sql, .zip, config files |
| **Open Redirects** | redirect/next/return_url in forms and JS |
| **Source Maps** | sourceMappingURL exposure |
| **robots.txt** | Disallowed paths, sitemap discovery |
| **GraphQL** | Introspection-enabled endpoints |
| **JWT Analysis** | Decode tokens, detect alg=none bypass |
| **HTML Comments** | Find TODO, password, secret comments |
| **Tech Hints** | WordPress/jQuery/Nginx CVE alerts |
| **Security Score** | 0-100 score with letter grade (A+ to F) |

---

## Installation

### Requirements

- Python 3.11 or higher
- pip

### Install from source

```bash
git clone https://github.com/yourusername/mattew.git
cd mattew
pip install -e .
```

### Install with dependencies

```bash
pip install -e ".[dev]"
```

This installs:
- `aiohttp` — async HTTP client
- `rich` — terminal UI
- `pytest` — testing (dev)

### Verify installation

```bash
mattew --version
# mattew 0.1.0
```

---

## Usage

### Basic scan

```bash
mattew https://target.com
```

### Save HTML report

```bash
mattew https://target.com -f html -o report.html
```

### Save JSON for automation

```bash
mattew https://target.com -f json -o results.json
```

### Deep scan

```bash
mattew https://target.com -d 5 -p 200
```

### Polite crawling

```bash
mattew https://target.com --delay 1
```

---

## All Commands

| Command | Description | Default |
|---------|-------------|---------|
| `mattew <target>` | Target URL to scan | required |
| `-d`, `--depth` | Crawl depth | 3 |
| `-p`, `--max-pages` | Max pages to scan | 100 |
| `-c`, `--concurrency` | Parallel requests | 10 |
| `-t`, `--timeout` | Request timeout (seconds) | 15 |
| `-f`, `--format` | Output format | text |
| `-o`, `--output` | Save to file | stdout |
| `--delay` | Delay between requests | 0 |
| `--follow-external` | Follow external links | off |
| `--user-agent` | Custom User-Agent | mattew/0.1 |
| `--no-robots` | Skip robots.txt | off |
| `--no-sitemap` | Skip sitemap.xml | off |
| `-v`, `--verbose` | Verbose logging | off |
| `--version` | Show version | — |
| `-h`, `--help` | Show help | — |

---

## Output Formats

### Text (default)

```bash
mattew https://target.com
```

Rich terminal output with colored panels, score, and findings.

### JSON

```bash
mattew https://target.com -f json -o results.json
```

Machine-readable output for automation and CI/CD.

### Markdown

```bash
mattew https://target.com -f markdown -o report.md
```

Markdown tables for documentation and GitHub.

### HTML

```bash
mattew https://target.com -f html -o report.html
```

Professional report with:
- Security score with letter grade
- Technology stack
- All findings in tables
- Pages scanned list
- Sidebar navigation

---

## Examples

```bash
# Quick recon
mattew https://example.com

# Full recon with report
mattew https://example.com -d 5 -p 200 -f html -o report.html

# JSON for scripts
mattew https://example.com -f json | jq '.meta.total_findings'

# Polite scanning
mattew https://example.com --delay 1 --no-robots

# Follow external links
mattew https://example.com --follow-external

# Custom user agent
mattew https://example.com --user-agent "MyBot/1.0"

# Verbose debugging
mattew https://example.com -v
```

---

## Test Results

| Target | Pages | Findings | Time | Score |
|--------|-------|----------|------|-------|
| nasa.gov | 22 | 396 | 10s | 66/100 (C) |
| github.com | 21 | 759 | 18s | — |
| httpbin.org | 5 | 32 | 4s | 45/100 (D) |
| example.com | 1 | 6 | 1s | 91/100 (A) |

---

## Architecture

```
mattew/
├── src/mattew/
│   ├── cli.py              # Rich CLI with banner
│   ├── crawler.py           # Async BFS crawler
│   ├── models.py            # Data models + scoring
│   ├── output.py            # Multi-format output
│   ├── html_report.py       # Professional HTML report
│   └── extractors/
│       ├── endpoints.py     # Links, fetch, actions
│       ├── javascript.py    # Script analysis
│       ├── api_routes.py    # REST, GraphQL, WebSocket
│       ├── parameters.py    # Forms, query params
│       ├── secrets.py       # Credentials (format-specific)
│       ├── fingerprint.py   # Tech detection
│       ├── security.py      # Headers, CORS, cookies
│       └── attack_surface.py # Debug, backups, redirects
├── tests/
│   ├── test_extractors.py
│   └── test_fingerprint_security.py
├── pyproject.toml
├── README.md
└── .gitignore
```

---

## Development

### Run tests

```bash
pytest
```

### Add new extractor

1. Create file in `src/mattew/extractors/`
2. Write function that takes `(html, url)` and returns `list[Finding]`
3. Add to `src/mattew/extractors/__init__.py`
4. Import and use in `src/mattew/crawler.py`

---

## License

MIT

---

## Disclaimer

This tool is for **authorized security testing** and **bug bounty programs** only. Always get permission before scanning targets you don't own.

---

## Contributing

1. Fork the repo
2. Create a branch (`git checkout -b feature/amazing`)
3. Commit (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing`)
5. Open a Pull Request

---

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/mattew/issues)
- Docs: [README](README.md)
