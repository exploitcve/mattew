"""Professional HTML report — centered, full-page, bug bounty ready."""

import html as _h
from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import CrawlResult


def _e(t: str) -> str:
    return _h.escape(str(t))


def _sc(s: str) -> str:
    return {"critical":"#ef4444","high":"#f97316","medium":"#eab308","low":"#3b82f6","info":"#6b7280"}.get(s,"#6b7280")


def _tl(ft: str) -> str:
    return {"endpoint":"Endpoints","javascript":"JavaScript","api_route":"API Routes","parameter":"Parameters","secret":"Secrets","file":"Sensitive Files","header":"Security Headers","info":"Intelligence","subdomain":"Subdomains"}.get(ft,ft.replace("_"," ").title())


def _ti(ft: str) -> str:
    return {"endpoint":"&#128279;","javascript":"&#128220;","api_route":"&#128225;","parameter":"&#128273;","secret":"&#128272;","file":"&#128196;","header":"&#128737;","info":"&#128161;","subdomain":"&#127760;"}.get(ft,"&#128196;")


def _score_c(s: int) -> str:
    if s >= 85: return "#22c55e"
    if s >= 70: return "#eab308"
    if s >= 50: return "#f97316"
    return "#ef4444"


def generate_html(result: CrawlResult) -> str:
    sm = result.summary()
    sec = result.security_score()
    bt = {}
    for f in result.findings:
        bt.setdefault(f.type.value, []).append(f)
    bs = {}
    for f in result.findings:
        bs.setdefault(f.severity.value, []).append(f)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sc = _score_c(sec["score"])
    target = sm["target"]
    domain = urlparse(target).netloc

    # ── Nav ──────────────────────────────────────────────────────────────
    nav_order = [("secret","Secrets"),("header","Headers"),("subdomain","Subdomains"),
                 ("file","Files"),("api_route","API Routes"),("parameter","Parameters"),
                 ("endpoint","Endpoints"),("javascript","JavaScript"),("info","Intel")]
    nav_items = []
    for ft, label in nav_order:
        c = len(bt.get(ft,[]))
        if c > 0:
            nav_items.append(f'<a href="#s-{ft}" class="ni">{_ti(ft)} {label}<span class="nc">{c}</span></a>')
    nav_html = "\n".join(nav_items)

    # ── Tech ─────────────────────────────────────────────────────────────
    cat_c = {"cms":"#22c55e","framework":"#a78bfa","server":"#38bdf8","library":"#fbbf24","analytics":"#f472b6","cdn":"#6b7280"}
    tech_html = ""
    for t in result.tech_stack:
        c = cat_c.get(t["category"],"#6b7280")
        tech_html += f'<div class="tb"><span class="tc" style="color:{c}">{_e(t["category"].upper())}</span><span class="tn">{_e(t["name"])}</span><span class="tv">{_e(t.get("version","—"))}</span></div>'
    if not tech_html:
        tech_html = '<p style="color:#52525b;font-size:.8rem">No technologies detected</p>'

    # ── Pages ────────────────────────────────────────────────────────────
    pages = sorted(result.urls_visited)
    pages_html = "".join(f'<div class="pg"><span class="pn">{i}</span><span class="pu" title="{_e(u)}">{_e(u[:80])}</span></div>' for i, u in enumerate(pages, 1))

    # ── Sections ─────────────────────────────────────────────────────────
    sec_order = [
        ("secret","&#128272; Secrets & Credentials","Hardcoded API keys, tokens, private keys."),
        ("header","&#128737; Security Headers","HTTP header analysis, CORS, cookie security."),
        ("subdomain","&#127760; Subdomains","Internal subdomains from HTML references."),
        ("file","&#128196; Sensitive Files","Backup files, source maps, sensitive references."),
        ("api_route","&#128225; API Routes","REST, GraphQL, WebSocket endpoints."),
        ("parameter","&#128273; Parameters","Form inputs, hidden fields, query params."),
        ("endpoint","&#128279; Endpoints","All URLs, links, forms, navigation."),
        ("javascript","&#128220; JavaScript","Script files and inline analysis."),
        ("info","&#128161; Intelligence","Tech detection, vulnerability hints."),
    ]
    sections_html = ""
    for ft, title, desc in sec_order:
        items = bt.get(ft, [])
        if not items:
            continue
        rows = ""
        for f in sorted(items, key=lambda x: ["critical","high","medium","low","info"].index(x.severity.value)):
            rows += f'<tr><td><span class="b" style="background:{_sc(f.severity.value)}">{f.severity.value.upper()}</span></td><td class="mo">{_e(f.value[:120])}</td><td class="src">{_e(f.source)}</td><td class="ct">{_e(f.context[:90])}</td></tr>'
        sections_html += f'''<div class="sec" id="s-{ft}">
<div class="sh"><h2>{title}</h2><span class="cb">{len(items)}</span></div>
<p class="sd">{desc}</p>
<div class="tw"><table class="ft"><thead><tr><th>Sev</th><th>Value</th><th>Source</th><th>Context</th></tr></thead><tbody>{rows}</tbody></table></div>
</div>'''

    # ── Deductions ───────────────────────────────────────────────────────
    ded_html = ""
    for d in sec["deductions"][:15]:
        ded_html += f'<div class="dd">{_e(d)}</div>'
    if not ded_html:
        ded_html = '<div class="dd">No deductions — clean scan</div>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mattew — {_e(domain)}</title>
<style>
:root{{--bg:#09090b;--bg2:#18181b;--bg3:#27272a;--bd:#27272a;--tx:#e4e4e7;--tx2:#a1a1aa;--tx3:#52525b;--cy:#22d3ee;--rd:#ef4444;--or:#f97316;--yl:#eab308;--bl:#3b82f6;--gn:#22c55e;--pp:#a78bfa}}
*{{margin:0;padding:0;box-sizing:border-box}}
html{{scroll-behavior:smooth}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;background:var(--bg);color:var(--tx);line-height:1.5;min-height:100vh}}
::selection{{background:var(--cy);color:var(--bg)}}
::-webkit-scrollbar{{width:5px}}::-webkit-scrollbar-track{{background:var(--bg2)}}::-webkit-scrollbar-thumb{{background:var(--bg3);border-radius:3px}}

.wrap{{max-width:1100px;margin:0 auto;padding:1.5rem}}

/* Header */
.hdr{{text-align:center;padding:2rem 0 1.5rem;border-bottom:1px solid var(--bd);margin-bottom:1.5rem}}
.hdr h1{{font-size:2rem;margin-bottom:.25rem}}.hdr h1 span{{color:var(--cy)}}
.hdr .tg{{color:var(--cy);font-family:monospace;font-size:.9rem;margin-bottom:.5rem}}
.hdr .meta{{display:flex;justify-content:center;flex-wrap:wrap;gap:1rem;color:var(--tx3);font-size:.8rem}}

/* Nav */
.nav{{display:flex;flex-wrap:wrap;justify-content:center;gap:.4rem;margin-bottom:1.5rem;padding:1rem;background:var(--bg2);border:1px solid var(--bd);border-radius:8px}}
.ni{{display:inline-flex;align-items:center;gap:.3rem;padding:.35rem .6rem;border-radius:5px;color:var(--tx2);text-decoration:none;font-size:.75rem;transition:all .15s;background:var(--bg)}}
.ni:hover{{background:var(--bg3);color:#fff}}
.nc{{background:var(--bg3);color:var(--cy);font-size:.6rem;padding:.1rem .3rem;border-radius:8px}}

/* Score cards */
.sr{{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem;margin-bottom:1.5rem}}
.sc{{background:var(--bg2);border:1px solid var(--bd);border-radius:10px;padding:1.25rem;text-align:center;transition:transform .2s}}
.sc:hover{{transform:translateY(-2px)}}
.sring{{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto .75rem;font-size:1.5rem;font-weight:700;color:#fff}}
.sbig{{font-size:2rem;font-weight:700}}.slb{{color:var(--tx3);font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;margin-top:.2rem}}

/* Sections */
.sec{{background:var(--bg2);border:1px solid var(--bd);border-radius:10px;padding:1.25rem;margin-bottom:1.25rem}}
.sh{{display:flex;align-items:center;gap:.6rem;margin-bottom:.4rem}}.sh h2{{font-size:1.05rem}}
.cb{{background:var(--bg3);color:var(--cy);font-size:.65rem;padding:.12rem .45rem;border-radius:8px;font-weight:600}}
.sd{{color:var(--tx3);font-size:.8rem;margin-bottom:.75rem}}

/* Table */
.tw{{overflow-x:auto}}
.ft{{width:100%;border-collapse:collapse;font-size:.78rem;min-width:550px}}
.ft th{{text-align:left;padding:.5rem;color:var(--tx3);border-bottom:2px solid var(--bd);font-size:.7rem;text-transform:uppercase;letter-spacing:.04em}}
.ft td{{padding:.4rem .5rem;border-bottom:1px solid #1f1f23;vertical-align:top}}
.ft tr:hover{{background:rgba(39,39,42,.3)}}
.mo{{font-family:'SF Mono','Fira Code',monospace;font-size:.72rem;word-break:break-all;max-width:300px}}
.ct{{color:var(--tx3);font-size:.72rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.src{{font-size:.72rem;color:var(--tx2);white-space:nowrap}}
.b{{color:#fff;padding:.08rem .35rem;border-radius:3px;font-size:.6rem;font-weight:600;white-space:nowrap}}

/* Tech */
.tb{{display:flex;align-items:center;gap:.5rem;padding:.4rem .7rem;background:var(--bg);border:1px solid var(--bd);border-radius:5px;margin-bottom:.3rem}}
.tc{{font-size:.65rem;font-weight:700;min-width:70px}}
.tn{{font-weight:600;font-size:.85rem}}.tv{{color:var(--tx3);font-size:.8rem;margin-left:auto}}

/* Pages */
.pgs{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.3rem;max-height:350px;overflow-y:auto;padding:.25rem}}
.pg{{display:flex;align-items:center;gap:.4rem;padding:.3rem .5rem;background:var(--bg);border:1px solid var(--bd);border-radius:4px;font-size:.72rem}}
.pn{{color:var(--cy);font-weight:600;min-width:20px;font-size:.7rem}}.pu{{color:var(--tx2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}

/* Deductions */
.dd{{padding:.3rem .5rem;background:var(--bg);border:1px solid var(--bd);border-radius:4px;font-size:.75rem;margin-bottom:.3rem;font-family:monospace}}

/* Footer */
.fo{{text-align:center;color:var(--tx3);font-size:.7rem;padding:1.5rem 0;border-top:1px solid var(--bd);margin-top:1.5rem}}

/* Mobile */
@media(max-width:768px){{
  .sr{{grid-template-columns:repeat(2,1fr)}}
  .hdr h1{{font-size:1.5rem}}
  .mo{{max-width:150px}}
  .wrap{{padding:1rem}}
}}
@media(max-width:480px){{
  .sr{{grid-template-columns:1fr}}
  .nav{{gap:.25rem}}
  .ni{{font-size:.7rem;padding:.3rem .5rem}}
}}
@media print{{
  .sec{{break-inside:avoid}}
}}
</style>
</head>
<body>
<div class="wrap">

<div class="hdr">
<h1><span>mattew</span> v0.1.0</h1>
<div class="tg">{_e(target)}</div>
<div class="meta">
<span>Pages: {sm["urls_visited"]}</span>
<span>Findings: {sm["total_findings"]}</span>
<span>Time: {sm["scan_time"]}s</span>
<span>{now}</span>
</div>
</div>

<div class="nav">
{nav_html}
<a href="#s-pages" class="ni">&#128196; Pages<span class="nc">{sm["urls_visited"]}</span></a>
<a href="#s-tech" class="ni">&#128295; Tech<span class="nc">{len(result.tech_stack)}</span></a>
<a href="#s-score" class="ni">&#127919; Score</a>
</div>

<div class="sr" id="s-score">
<div class="sc"><div class="sring" style="background:conic-gradient({sc} {sec["score"]}%,var(--bg3) 0)">{sec["score"]}</div><div class="sbig" style="color:{sc}">{sec["rating"]}</div><div class="slb">Security Score</div></div>
<div class="sc"><div class="sbig" style="color:var(--cy)">{sm["total_findings"]}</div><div class="slb">Total Findings</div></div>
<div class="sc"><div class="sbig" style="color:var(--rd)">{len(bs.get("critical",[]))+len(bs.get("high",[]))}</div><div class="slb">Critical + High</div></div>
<div class="sc"><div class="sbig" style="color:var(--yl)">{len(bs.get("medium",[]))}</div><div class="slb">Medium</div></div>
</div>

<div class="sec">
<div class="sh"><h2>&#127919; Score Breakdown</h2></div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem">
<div>
<table class="ft" style="min-width:auto"><thead><tr><th>Severity</th><th>Count</th><th>Points</th></tr></thead><tbody>
<tr><td><span class="b" style="background:var(--rd)">CRITICAL</span></td><td>{len(bs.get("critical",[]))}</td><td>-20</td></tr>
<tr><td><span class="b" style="background:var(--or)">HIGH</span></td><td>{len(bs.get("high",[]))}</td><td>-8</td></tr>
<tr><td><span class="b" style="background:var(--yl)">MEDIUM</span></td><td>{len(bs.get("medium",[]))}</td><td>-2 (max 5)</td></tr>
<tr><td><span class="b" style="background:var(--bl)">LOW</span></td><td>{len(bs.get("low",[]))}</td><td>0</td></tr>
<tr><td><span class="b" style="background:#6b7280">INFO</span></td><td>{len(bs.get("info",[]))}</td><td>0</td></tr>
</tbody></table>
</div>
<div><p style="color:var(--tx3);font-size:.75rem;margin-bottom:.4rem">Deductions:</p>{ded_html}</div>
</div>
</div>

<div class="sec" id="s-tech">
<div class="sh"><h2>&#128295; Technology Stack</h2></div>
{tech_html}
</div>

<div class="sec" id="s-pages">
<div class="sh"><h2>&#128196; Pages Scanned ({sm["urls_visited"]})</h2></div>
<div class="pgs">{pages_html}</div>
</div>

{sections_html}

<div class="fo"><strong>mattew v0.1.0</strong> — Web application surface mapper for security research<br>For authorized security testing and bug bounty programs only.</div>

</div>
</body>
</html>'''
