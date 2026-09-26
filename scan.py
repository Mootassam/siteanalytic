"""
Scan orchestrator: runs every analyzer for a URL, streams progress, and
assembles the final intelligence report (including the aggregated "Website DNA"
and optional multi-device screenshots).
"""

from __future__ import annotations

import concurrent.futures as futures
import re
import urllib.parse
from datetime import datetime, timezone

import analyzers as A
import intel
import recon as R


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _origin(url: str) -> str:
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def normalize(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url


def run_scan(url: str, opts: dict | None = None, progress=None) -> dict:
    opts = opts or {}
    url = normalize(url)
    host = intel._host(url)
    origin = _origin(url)
    report: dict = {
        "input_url": url, "host": host, "scanned_at": _now(),
        "errors": [], "phases": {},
    }
    t0 = datetime.now(timezone.utc)

    def step(name, pct, msg=""):
        report["phases"][name] = "done"
        if progress:
            progress(pct, name, msg)

    def guard(name, fn):
        try:
            return fn()
        except Exception as e:
            report["errors"].append({"phase": name, "error": intel._short(e)})
            return None

    if progress:
        progress(3, "http", "fetching homepage")
    # 1) homepage fetch (drives HTTP, headers, tech, SEO, security, cookies)
    home = intel.fetch(url, timeout=intel.DEFAULT_TIMEOUT)
    if not home.get("ok") and home.get("status", 0) == 0:
        report["errors"].append({"phase": "http", "error": home.get("error", "could not connect")})
    final_url = home.get("url", url)
    report["http"] = {
        "status": home.get("status"), "final_url": final_url,
        "redirect_chain": home.get("redirects", []),
        "response_ms": home.get("total_ms"), "ttfb_ms": home.get("ttfb_ms"),
        "http_version": home.get("http_version"),
        "content_type": home.get("headers", {}).get("Content-Type", ""),
        "content_length": home.get("content_length"),
        "content_encoding": home.get("content_encoding", ""),
        "server": home.get("headers", {}).get("Server", ""),
        "powered_by": home.get("headers", {}).get("X-Powered-By", ""),
    }
    headers = home.get("headers", {})
    report["headers"] = headers
    html = home.get("text", "")
    scripts = [urllib.parse.urljoin(final_url, s) for _q, s in A.SCRIPT_SRC.findall(html)]
    cookies_raw = "; ".join(v for k, v in headers.items() if k.lower() == "set-cookie")
    step("http", 12)

    # 2) parallel independent probes
    if progress:
        progress(15, "probes", "DNS · SSL · RDAP · IP")
    with futures.ThreadPoolExecutor(max_workers=6) as ex:
        f_dns = ex.submit(guard, "dns", lambda: intel.dns_records(host))
        f_ssl = ex.submit(guard, "ssl", lambda: intel.ssl_info(host))
        f_rdap = ex.submit(guard, "domain", lambda: rdap_domain(host))
        f_hist = ex.submit(guard, "history", lambda: A.archive_history(url))
        dns = f_dns.result() or {"records": {}}
        ssl_i = f_ssl.result() or {"available": False}
        rdap = f_rdap.result() or {}
        history = f_hist.result() or {"available": False}
    report["dns"] = dns
    report["ssl"] = ssl_i
    report["domain"] = rdap
    report["history"] = history

    # IP + ASN from resolved A/AAAA
    a_recs = [r["data"] for r in dns.get("records", {}).get("A", [])]
    aaaa = [r["data"] for r in dns.get("records", {}).get("AAAA", [])]
    ip = {"ipv4": a_recs, "ipv6": aaaa}
    if a_recs:
        ip.update(guard("asn", lambda: intel.asn_lookup(a_recs[0])) or {})
    report["ip"] = ip
    report["email_security"] = guard("email", lambda: A.email_security(host, dns.get("records", {}))) or {}
    step("probes", 32)

    # 3) content analysis (tech / seo / security / cookies)
    if progress:
        progress(38, "content", "fingerprinting technologies")
    report["technologies"] = guard("tech", lambda: A.detect_tech(html, headers, cookies_raw, scripts)) or []
    report["seo"] = guard("seo", lambda: A.seo_analysis(html, final_url)) or {}
    report["security_headers"] = guard("security", lambda: A.security_headers(headers)) or {}
    report["cookies"] = guard("cookies", lambda: A.parse_cookies(headers)) or []
    step("content", 48)

    # 4) robots + sitemap
    if progress:
        progress(52, "robots", "robots.txt · sitemap")
    robots = guard("robots", lambda: A.robots_txt(origin)) or {"present": False}
    report["robots"] = robots
    sitemap = guard("sitemap", lambda: A.sitemap_analysis(origin, robots.get("sitemaps", []))) or {"present": False}
    report["sitemap"] = sitemap
    step("robots", 60)

    # 5) crawl (pages / links / assets / apis / external domains / public files)
    max_pages = int(opts.get("max_pages", 30))
    max_depth = int(opts.get("max_depth", 2))

    def crawl_progress(done, total, cur):
        if progress:
            progress(60 + int(done / max(1, total) * 25), "crawl", f"{done}/{total}  {cur}")

    cr = guard("crawl", lambda: A.crawl(final_url, max_pages, max_depth, crawl_progress)) or {}
    report["crawl"] = {"pages": cr.get("pages", []), "page_count": cr.get("page_count", 0)}
    report["links"] = link_summary(cr.get("links", []))
    report["assets"] = asset_summary(cr.get("assets", []))
    report["javascript"] = js_summary(cr.get("assets", []), report["technologies"])
    report["apis"] = api_summary(cr.get("apis", []), cr.get("websockets", []), final_url)
    report["public_files"] = cr.get("public_files", [])
    report["external_domains"] = cr.get("external_domains", [])
    report["contacts"] = {"emails": cr.get("emails", []), "socials": cr.get("socials", [])}
    # compare sitemap vs crawl
    if sitemap.get("present"):
        crawled = {p["url"] for p in cr.get("pages", [])}
        sm_urls = set(sitemap.get("urls", []))
        report["sitemap"]["not_crawled"] = list(sm_urls - crawled)[:200]
        report["sitemap"]["crawled_not_in_sitemap"] = list(crawled - sm_urls)[:200]
    step("crawl", 86)

    # 6) deep checks (opt-in)
    if opts.get("deep", False):
        if progress:
            progress(84, "deep", "security / best-practice checks")
        report["deep"] = guard("deep", lambda: A.deep_checks(origin, home, True)) or {}
        step("deep", 86)

    # 7) deep intelligence / recon (opt-in): passive OSINT from public sources
    if opts.get("recon"):
        def rp(pct, msg):
            if progress:
                progress(pct, "recon", msg)
        rp(87, "subdomains · certificate transparency")
        subs = guard("subdomains", lambda: R.subdomains(host)) or {"records": [], "unique_ips": [], "ip_index": {}}
        report["subdomains"] = subs
        report["cert_history"] = guard("cert_history", lambda: R.cert_history(host)) or {"available": False}
        rp(89, "exposed services · known CVEs")
        all_ips = list(dict.fromkeys((report["ip"].get("ipv4") or []) + subs.get("unique_ips", [])))
        ports = guard("ports", lambda: R.passive_ports(all_ips)) or {"available": False}
        report["passive_ports"] = ports
        report["infrastructure"] = guard("infra", lambda: R.infrastructure(subs, report["ip"].get("ipv4") or [], ports)) or {"available": False}
        rp(91, "deep DNS · takeover · reputation")
        report["dns_deep"] = guard("dns_deep", lambda: R.dns_deep(host, subs)) or {}
        mx_ips = guard("mx_ips", lambda: mx_addresses(dns.get("records", {}))) or []
        report["reputation"] = guard("reputation", lambda: R.reputation(report["ip"].get("ipv4") or [], mx_ips)) or {}
        rp(92, "look-alike domains · owner pivots")
        report["typosquats"] = guard("typosquats", lambda: R.typosquats(host)) or {}
        report["pivots"] = guard("pivots", lambda: R.pivots(origin, html, dns.get("records", {}))) or {}
        rp(93, "platform · versions · exposures")
        report["wordpress"] = guard("wordpress", lambda: A.wordpress_scan(origin, html)) or {"is_wordpress": False}
        report["tech_cve"] = guard("tech_cve", lambda: A.tech_cve(report["technologies"])) or {}
        report["secrets"] = guard("secrets", lambda: A.secret_scan(origin, html, scripts)) or {}
        report["cloud_storage"] = guard("cloud", lambda: A.cloud_storage(origin, html, report["assets"].get("items", []))) or {}
        report["exposed_config"] = guard("config", lambda: A.exposed_config(origin)) or {}
        report["trust"] = guard("trust", lambda: R.trust_score(report)) or {}
        step("recon", 94)

    # 8) browser probe: performance + screenshots
    if progress:
        progress(95, "browser", "measuring performance · screenshots")
    probe = guard("browser", lambda: browser_probe(final_url, opts)) or {}
    report["performance"] = probe.get("performance", {})
    report["screenshots"] = probe.get("screenshots", {"available": False})
    step("browser", 97)
    if opts.get("recon") and report.get("trust"):
        report["trust"] = guard("trust", lambda: R.trust_score(report)) or report["trust"]

    # 8) DNA + score + findings
    report["dna"] = build_dna(report)
    report["score"] = build_score(report)
    report["findings"] = build_findings(report)
    report["duration_s"] = round((datetime.now(timezone.utc) - t0).total_seconds(), 1)
    if progress:
        progress(100, "done", "complete")
    return report


# --------------------------------------------------------------------------- #
# RDAP (domain WHOIS)
# --------------------------------------------------------------------------- #
def rdap_domain(host: str) -> dict:
    domain = intel._registrable(host)
    r = intel.fetch(f"https://rdap.org/domain/{domain}", timeout=12)
    if not r["ok"]:
        return {"domain": domain, "available": False, "error": f"RDAP HTTP {r['status']}"}
    import json
    data = json.loads(r["text"])
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = ""
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            vcard = ent.get("vcardArray", [None, []])[1]
            for item in vcard:
                if item and item[0] == "fn":
                    registrar = item[3]
    nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])]
    return {
        "domain": domain, "available": True, "registrar": registrar,
        "registered": events.get("registration"), "updated": events.get("last changed"),
        "expires": events.get("expiration"),
        "status": data.get("status", []), "nameservers": nameservers,
    }


# --------------------------------------------------------------------------- #
# Summaries
# --------------------------------------------------------------------------- #
def mx_addresses(records: dict) -> list[str]:
    """Resolve MX hostnames to IPv4 so reputation can check the mail servers."""
    ips = []
    for r in records.get("MX", [])[:5]:
        host = r["data"].split()[-1].rstrip(".") if r.get("data") else ""
        if host:
            ips += [a["data"] for a in intel.doh(host, "A")]
    return [ip for ip in dict.fromkeys(ips) if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip)]


def link_summary(links: list[dict]) -> dict:
    by = {"internal": [], "external": [], "mailto": [], "tel": [], "anchor": []}
    for l in links:
        t = l["type"]
        if t == "internal":
            by["internal"].append(l)
        elif t == "external":
            by["external"].append(l)
        elif t == "mailto":
            by["mailto"].append(l)
        elif t == "tel":
            by["tel"].append(l)
    uniq = {l["href"]: l for l in links if l["type"] in ("internal", "external")}
    return {
        "total": len(uniq), "internal": len(set(l["href"] for l in by["internal"])),
        "external": len(set(l["href"] for l in by["external"])),
        "mailto": sorted(set(l["href"] for l in by["mailto"]))[:50],
        "tel": sorted(set(l["href"] for l in by["tel"]))[:50],
        "external_list": sorted(set(l["href"] for l in by["external"]))[:300],
    }


def asset_summary(assets: list[dict]) -> dict:
    from collections import Counter
    by_type = Counter(a["type"] for a in assets)
    return {"total": len(assets), "by_type": dict(by_type), "items": assets[:1000]}


def js_summary(assets: list[dict], techs: list[dict]) -> dict:
    js = [a for a in assets if a["type"] == "js"]
    libs = [t for t in techs if t["category"] in ("JS library", "JS framework")]
    return {"count": len(js), "internal": sum(1 for a in js if a["internal"]),
            "external": sum(1 for a in js if not a["internal"]),
            "files": js[:300], "libraries": libs}


def api_summary(apis: list[str], ws: list[str], base: str) -> dict:
    host = intel._registrable(intel._host(base))
    items = []
    for a in apis:
        full = urllib.parse.urljoin(base, a)
        kind = "GraphQL" if "graphql" in a.lower() else "REST/JSON"
        items.append({"endpoint": a, "type": kind,
                      "internal": intel._registrable(intel._host(full)) == host})
    return {"count": len(items), "endpoints": items[:200],
            "websockets": [{"endpoint": w} for w in ws]}


def build_dna(r: dict) -> dict:
    techs = r.get("technologies", [])
    def cat(c):
        return [t["name"] for t in techs if t["category"] == c]
    ssl_i = r.get("ssl", {})
    return {
        "domain": r.get("host"),
        "ip": (r.get("ip", {}).get("ipv4") or ["—"])[0],
        "asn": r.get("ip", {}).get("asn", "—"),
        "org": r.get("ip", {}).get("org", "—"),
        "server": r.get("http", {}).get("server", "—") or "—",
        "cdn": ", ".join(cat("CDN")) or "—",
        "hosting": ", ".join(cat("Hosting")) or "—",
        "cms": ", ".join(cat("CMS") + cat("E-commerce") + cat("Website builder")) or "—",
        "frameworks": ", ".join(cat("JS framework") + cat("Backend")) or "—",
        "css": ", ".join(cat("CSS framework")) or "—",
        "js_libraries": ", ".join(cat("JS library")) or "—",
        "analytics": ", ".join(cat("Analytics")) or "—",
        "payment": ", ".join(cat("Payment")) or "—",
        "ssl": ssl_i.get("status", "—") if ssl_i.get("available") else "none",
        "ssl_issuer": ssl_i.get("issuer", "—"),
        "security_grade": r.get("security_headers", {}).get("grade", "—"),
        "pages_found": r.get("crawl", {}).get("page_count", 0),
        "assets_found": r.get("assets", {}).get("total", 0),
        "external_domains": len(r.get("external_domains", [])),
        "api_references": r.get("apis", {}).get("count", 0),
        "registrar": r.get("domain", {}).get("registrar", "—"),
        "expires": r.get("domain", {}).get("expires", "—"),
        "email_grade": r.get("email_security", {}).get("grade", "—"),
        "performance": r.get("performance", {}).get("score", "—"),
        "page_weight": r.get("performance", {}).get("weight_mb"),
        "subdomains": r.get("subdomains", {}).get("resolved") if r.get("subdomains") else None,
        "open_ports": sum(len(h.get("ports", [])) for h in r.get("passive_ports", {}).get("hosts", [])) or None,
        "trust": r.get("trust", {}).get("score") if r.get("trust") else None,
    }


GRADE_SCALE = ["F", "E", "D", "C", "B", "A", "A+"]


def _letter(score: int) -> str:
    for cut, g in [(97, "A+"), (90, "A"), (80, "B"), (70, "C"), (60, "D"), (45, "E")]:
        if score >= cut:
            return g
    return "F"


def build_score(r: dict) -> dict:
    # Security subscore
    sec = 0
    sh = r.get("security_headers", {})
    sec += (sh.get("present", 0) / max(1, sh.get("total", 10))) * 45
    ssl = r.get("ssl", {})
    if ssl.get("available"):
        sec += 30 if ssl.get("status") == "valid" else (10 if ssl.get("status") == "expiring soon" else 0)
    em = r.get("email_security", {})
    sec += {"A": 25, "B": 18, "C": 12, "D": 6, "F": 0}.get(em.get("grade"), 0)
    sec = min(100, round(sec))

    # SEO subscore
    seo = r.get("seo", {})
    seo_pts = sum([
        20 if seo.get("title") else 0, 15 if 10 <= (seo.get("title_length") or 0) <= 65 else 5,
        20 if seo.get("meta_description") else 0, 10 if seo.get("h1_count") == 1 else 0,
        10 if seo.get("canonical") else 0, 10 if seo.get("viewport") else 0,
        8 if seo.get("og") else 0, 7 if seo.get("structured_data") else 0,
    ])
    seo_score = min(100, seo_pts)

    perf = r.get("performance", {}).get("score")
    perf_score = perf if isinstance(perf, (int, float)) else 70

    # Best practices
    bp = 60
    deep = r.get("deep", {})
    if deep:
        checks = deep.get("checks", [])
        bp = round(sum(1 for c in checks if c.get("ok")) / max(1, len(checks)) * 100)
    else:
        http = r.get("http", {})
        bp = 70 + (10 if not http.get("powered_by") else 0) + (10 if r.get("robots", {}).get("present") else 0) + (10 if r.get("sitemap", {}).get("present") else 0)
        bp = min(100, bp)

    subs = {"security": sec, "performance": round(perf_score), "seo": seo_score, "best_practices": bp}
    overall = round(sec * 0.35 + perf_score * 0.25 + seo_score * 0.22 + bp * 0.18)
    return {"overall": overall, "grade": _letter(overall), "subscores": subs}


def build_findings(r: dict) -> list[dict]:
    f = []
    def add(sev, cat, title, detail=""):
        f.append({"severity": sev, "category": cat, "title": title, "detail": detail})

    ssl = r.get("ssl", {})
    if not ssl.get("available"):
        add("critical", "SSL", "No HTTPS / SSL certificate", ssl.get("error", ""))
    elif ssl.get("status") == "expired":
        add("critical", "SSL", "SSL certificate has expired", ssl.get("valid_to", ""))
    elif (ssl.get("days_remaining") or 999) < 21:
        add("warning", "SSL", f"SSL expires in {ssl.get('days_remaining')} days", ssl.get("valid_to", ""))

    sh = r.get("security_headers", {})
    missing = [h["header"] for h in sh.get("headers", []) if not h["present"] and h["key"] in
               ("content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options")]
    if missing:
        add("warning", "Security", f"{len(missing)} key security headers missing", ", ".join(missing))

    em = r.get("email_security", {})
    if em and em.get("spoofable"):
        why = []
        if not em.get("has_spf"): why.append("no SPF")
        if not em.get("has_dmarc"): why.append("no DMARC")
        elif em.get("dmarc_policy") not in ("quarantine", "reject"): why.append(f"DMARC p={em.get('dmarc_policy') or 'none'}")
        add("warning", "Email", "Domain may be spoofable in email", ", ".join(why))

    deep = r.get("deep", {})
    for c in deep.get("checks", []):
        if not c.get("ok"):
            add(c.get("severity", "warning"), "Best practice", c["name"], c.get("detail", ""))
    for ex in deep.get("exposed_files", []):
        add("critical", "Exposure", f"Sensitive file exposed: {ex['path']}", f"HTTP {ex['status']} · {ex['type']}")

    seo = r.get("seo", {})
    if not seo.get("title"):
        add("warning", "SEO", "Missing <title>")
    if not seo.get("meta_description"):
        add("info", "SEO", "Missing meta description")
    if seo.get("h1_count", 0) != 1:
        add("info", "SEO", f"{seo.get('h1_count', 0)} H1 tags (ideal: 1)")

    perf = r.get("performance", {})
    if perf.get("load", 0) > 4000:
        add("warning", "Performance", f"Slow load: {round(perf['load']/1000,1)}s", f"{perf.get('weight_mb')} MB, {perf.get('request_count')} requests")
    if (perf.get("weight_mb") or 0) > 3:
        add("info", "Performance", f"Heavy page: {perf.get('weight_mb')} MB")

    # ---- deep intelligence (recon) findings ----
    sec = r.get("secrets", {})
    if sec.get("count"):
        add("critical", "Exposure", f"{sec['count']} secret(s) exposed in public code",
            ", ".join(sorted({f['type'] for f in sec.get('findings', [])})))
    cs = r.get("cloud_storage", {})
    for b in cs.get("buckets", []):
        if b.get("public_listable"):
            add("critical", "Exposure", f"Public cloud bucket is listable: {b['bucket']}", b.get("provider", ""))
    dd = r.get("dns_deep", {})
    for tk in dd.get("takeover_risks", []):
        add("critical", "Takeover", f"Possible subdomain takeover: {tk['subdomain']}",
            f"dangling CNAME → {tk['provider']} ({tk['cname']})")
    rep = r.get("reputation", {})
    if rep.get("listed"):
        add("critical", "Reputation", f"IP on {len(rep.get('listings', []))} DNS blocklist(s)",
            ", ".join(sorted({x['blocklist'] for x in rep.get('listings', [])})))
    pp = r.get("passive_ports", {})
    if pp.get("vuln_count"):
        add("warning", "Vulnerabilities", f"{pp['vuln_count']} known CVE(s) on exposed services",
            ", ".join(pp.get("vuln_ids", [])[:8]))
    for rk in pp.get("risky_ports", [])[:6]:
        add("warning", "Exposure", f"Risky port {rk['port']} ({rk.get('name','')}) open on {rk['ip']}", rk.get("why", ""))
    tv = r.get("tech_cve", {})
    for o in tv.get("outdated", []):
        add("warning", "Vulnerabilities", f"{o['name']} {o['version']} is outdated (fix ≥ {o['fixed_in']})", o["advisory"])
    ec = r.get("exposed_config", {})
    for it in ec.get("items", []):
        add("warning", "Exposure", f"Public config exposed: {it['path']}", it.get("note", ""))
    wp = r.get("wordpress", {})
    if wp.get("is_wordpress"):
        if wp.get("rest_users_exposed"):
            add("info", "WordPress", f"{len(wp.get('users', []))} usernames exposed via REST API",
                "Restrict /wp-json/wp/v2/users")
        if wp.get("xmlrpc"):
            add("info", "WordPress", "XML-RPC is enabled", "Disable if unused (brute-force / pingback abuse)")
    subs = r.get("subdomains", {})
    if subs.get("staging"):
        add("info", "Exposure", f"{len(subs['staging'])} staging/internal subdomain(s) publicly resolvable",
            ", ".join(subs["staging"][:6]))
    if r.get("dns_deep") and not r["dns_deep"].get("dnssec"):
        add("info", "DNS", "DNSSEC is not enabled")
    ts = r.get("typosquats", {})
    if ts.get("with_mail"):
        add("warning", "Brand", f"{ts['with_mail']} look-alike domain(s) can send email (phishing risk)",
            ", ".join(d["domain"] for d in ts.get("registered", []) if d.get("has_mx"))[:200])
    elif ts.get("count"):
        add("info", "Brand", f"{ts['count']} look-alike domain(s) are registered")

    order = {"critical": 0, "warning": 1, "info": 2}
    good = not any(x["severity"] in ("critical", "warning") for x in f)
    if good:
        add("good", "Overall", "No critical issues found", "This site passes the key checks.")
    return sorted(f, key=lambda x: order.get(x["severity"], 3))


# --------------------------------------------------------------------------- #
# Browser probe: screenshots + real performance metrics (Playwright)
# --------------------------------------------------------------------------- #
PERF_JS = """() => {
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const res = performance.getEntriesByType('resource') || [];
  const by_type = {}; let transfer = nav.transferSize || 0;
  for (const r of res) {
    const b = r.transferSize || r.encodedBodySize || 0;
    transfer += b;
    const t = r.initiatorType || 'other';
    by_type[t] = (by_type[t] || 0) + b;
  }
  return {
    ttfb: Math.round(nav.responseStart || 0),
    dom_interactive: Math.round(nav.domInteractive || 0),
    dom_content_loaded: Math.round(nav.domContentLoadedEventEnd || 0),
    load: Math.round(nav.loadEventEnd || nav.duration || 0),
    transfer_bytes: transfer, request_count: res.length + 1, by_type,
    dom_nodes: document.getElementsByTagName('*').length,
  };
}"""


def browser_probe(url: str, opts: dict) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return {"screenshots": {"available": False, "reason": "Playwright not installed"}}
    import base64
    out = {"screenshots": {}, "performance": {}}
    try:
        with sync_playwright() as pw:
            browser = None
            for ch in (opts.get("channel") or "msedge", "chrome", None):
                try:
                    browser = pw.chromium.launch(channel=ch) if ch else pw.chromium.launch()
                    break
                except Exception:
                    continue
            if not browser:
                return {"screenshots": {"available": False, "reason": "no browser"}}
            try:
                ctx = browser.new_context(viewport={"width": 1366, "height": 900}, ignore_https_errors=True)
                page = ctx.new_page()
                page.goto(url, wait_until="networkidle", timeout=30000)
                try:
                    out["performance"] = page.evaluate(PERF_JS)
                except Exception:
                    pass
                if opts.get("screenshots", True):
                    png = page.screenshot(full_page=True, type="jpeg", quality=68)
                    out["screenshots"]["desktop"] = "data:image/jpeg;base64," + base64.b64encode(png).decode()
                ctx.close()
            except Exception as e:
                out["screenshots"]["desktop_error"] = intel._short(e)
            if opts.get("screenshots", True):
                try:
                    ctx = browser.new_context(viewport={"width": 390, "height": 844}, is_mobile=True, ignore_https_errors=True)
                    page = ctx.new_page()
                    page.goto(url, wait_until="networkidle", timeout=25000)
                    png = page.screenshot(type="jpeg", quality=68)
                    out["screenshots"]["mobile"] = "data:image/jpeg;base64," + base64.b64encode(png).decode()
                    ctx.close()
                except Exception as e:
                    out["screenshots"]["mobile_error"] = intel._short(e)
            browser.close()
    except Exception as e:
        return {"screenshots": {"available": False, "reason": intel._short(e)}}
    out["screenshots"]["available"] = any(k in out["screenshots"] for k in ("desktop", "mobile"))
    if out["performance"].get("transfer_bytes"):
        out["performance"] = _perf_grade(out["performance"])
    return out


def _perf_grade(p: dict) -> dict:
    mb = p["transfer_bytes"] / 1_000_000
    # Sustainable Web Design model: ~0.494 g CO2 per MB transferred (global grid)
    p["co2_grams"] = round(mb * 0.494, 3)
    load = p.get("load", 0)
    score = 100
    if load > 1000:
        score -= min(40, (load - 1000) / 100)
    if mb > 1:
        score -= min(35, (mb - 1) * 12)
    if p.get("request_count", 0) > 50:
        score -= min(15, (p["request_count"] - 50) / 6)
    p["score"] = max(0, round(score))
    p["weight_mb"] = round(mb, 2)
    return p
