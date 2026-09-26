"""
Deep intelligence (recon) module — passive OSINT from PUBLIC sources only.

Everything here reads data that is already public: Certificate Transparency logs
(crt.sh), DNS over HTTPS, Shodan's free InternetDB (no key), public DNS blocklists,
and what the site itself serves. Nothing authenticates, brute-forces or exploits.
Where an exposure is found (an API key in public JS, a listable bucket) it is
REPORTED — masked — so the owner can fix it, never used or exfiltrated.

Capabilities:
  subdomains()        Certificate Transparency + DNS -> live subdomains, staging flags
  cert_history()      every SSL certificate ever issued (crt.sh) -> timeline
  infrastructure()    IPs -> ASN / org / country, shared-host hostnames (reverse-IP-ish)
  passive_ports()     Shodan InternetDB -> open ports, software (CPEs), known CVEs
  dns_deep()          DNSSEC, BIMI, MTA-STS, DKIM selectors, subdomain-takeover risk
  typosquats()        look-alike domains that are registered (brand protection)
  reputation()        public DNS blocklists for the mail/host IPs
  pivots()            GA / GTM / AdSense / Pixel IDs + favicon hash for owner research
  trust_score()       aggregate legitimacy / scam rating with reasons
"""

from __future__ import annotations

import concurrent.futures as futures
import json
import re
import socket
import urllib.parse
from datetime import datetime, timezone

import intel
from intel import doh, fetch, _host, _registrable, _short

INTERNETDB = "https://internetdb.shodan.io/{ip}"
CRTSH = "https://crt.sh/?q={q}&output=json"


def _reg(host):
    return _registrable(host)


# --------------------------------------------------------------------------- #
# Certificate Transparency (crt.sh): subdomains + full certificate history
# --------------------------------------------------------------------------- #
def _crtsh(domain: str) -> list[dict]:
    for q in (f"%25.{domain}", domain):
        r = fetch(CRTSH.format(q=q), timeout=25)
        if r["ok"] and r["text"].strip().startswith("["):
            try:
                return json.loads(r["text"])
            except Exception:
                continue
    return []


STAGING_RE = re.compile(r"\b(dev|test|stag|staging|uat|qa|beta|preview|sandbox|demo|internal|"
                        r"admin|dashboard|portal|vpn|git|jenkins|jira|grafana|kibana|api|"
                        r"mail|webmail|cpanel|whm|ftp|db|sql|backup|old|new|temp)\b", re.I)


def _classify_sub(label: str) -> str:
    if re.search(r"\b(dev|test|stag|staging|uat|qa|beta|preview|sandbox|demo|localhost)\b", label, re.I):
        return "staging"
    if re.search(r"\b(admin|dashboard|portal|cpanel|whm|jenkins|jira|grafana|kibana|vpn|git|manage)\b", label, re.I):
        return "internal"
    if re.search(r"\b(mail|webmail|smtp|imap|mx|pop)\b", label, re.I):
        return "mail"
    if re.search(r"\b(api|graphql|cdn|static|assets|img|media|files|download)\b", label, re.I):
        return "service"
    return "public"


def subdomains(domain: str, resolve_limit: int = 120, progress=None) -> dict:
    """Discover subdomains from CT logs, resolve them, flag staging/internal ones."""
    domain = _reg(domain)
    names: set[str] = set()
    for row in _crtsh(domain):
        for nv in str(row.get("name_value", "")).splitlines():
            nv = nv.strip().lstrip("*.").lower()
            if nv.endswith("." + domain) or nv == domain:
                if "@" not in nv and re.match(r"^[a-z0-9._-]+$", nv):
                    names.add(nv)
    # a few common guesses in case CT is thin
    for g in ("www", "mail", "api", "app", "dev", "staging", "admin", "blog", "shop", "cdn", "m", "portal"):
        names.add(f"{g}.{domain}")
    names.discard(domain)
    ordered = sorted(names)[:resolve_limit]

    def resolve(sub):
        a = [r["data"] for r in doh(sub, "A")]
        cname = [r["data"].rstrip(".") for r in doh(sub, "CNAME")]
        live = bool(a)
        label = sub[: -len(domain) - 1]
        return {"subdomain": sub, "ips": a, "cname": cname[0] if cname else "",
                "live": live, "type": _classify_sub(label)}

    out = []
    with futures.ThreadPoolExecutor(max_workers=16) as ex:
        for i, res in enumerate(ex.map(resolve, ordered)):
            out.append(res)
            if progress and i % 10 == 0:
                progress(i, len(ordered))
    live = [s for s in out if s["live"] or s["cname"]]
    live.sort(key=lambda s: (s["type"] != "staging", s["subdomain"]))
    ip_index: dict[str, list[str]] = {}
    for s in live:
        for ip in s["ips"]:
            ip_index.setdefault(ip, []).append(s["subdomain"])
    return {
        "total_found": len(names), "resolved": len(live), "records": live[:300],
        "staging": [s["subdomain"] for s in live if s["type"] in ("staging", "internal")],
        "unique_ips": sorted(ip_index),
        "ip_index": {ip: subs for ip, subs in ip_index.items()},
    }


def cert_history(domain: str) -> dict:
    domain = _reg(domain)
    rows = _crtsh(domain)
    if not rows:
        return {"available": False}
    seen, certs = set(), []
    issuers = {}
    for row in rows:
        key = (row.get("serial_number"), row.get("not_before"))
        if key in seen:
            continue
        seen.add(key)
        iss = re.sub(r".*?O=([^,]+).*", r"\1", row.get("issuer_name", "")) or row.get("issuer_name", "")
        iss = iss.strip()[:60]
        issuers[iss] = issuers.get(iss, 0) + 1
        certs.append({"issuer": iss, "not_before": (row.get("not_before") or "")[:10],
                      "not_after": (row.get("not_after") or "")[:10],
                      "names": row.get("name_value", "").replace("\n", ", ")[:120]})
    certs.sort(key=lambda c: c["not_before"], reverse=True)
    dates = [c["not_before"] for c in certs if c["not_before"]]
    return {"available": True, "total": len(certs), "first_seen": min(dates) if dates else "",
            "last_seen": max(dates) if dates else "",
            "issuers": sorted(issuers.items(), key=lambda x: -x[1]),
            "certs": certs[:100]}


# --------------------------------------------------------------------------- #
# Shodan InternetDB (free, no key): ports, software, known CVEs, shared hosts
# --------------------------------------------------------------------------- #
_PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
               110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
               587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
               3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
               8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
               11211: "Memcached", 2375: "Docker", 5601: "Kibana", 9000: "misc"}
RISKY_PORTS = {23: "Telnet is unencrypted", 3389: "RDP exposed to the internet",
               3306: "MySQL reachable publicly", 5432: "PostgreSQL reachable publicly",
               6379: "Redis often needs no auth", 27017: "MongoDB reachable publicly",
               9200: "Elasticsearch often unauthenticated", 11211: "Memcached is a DDoS/abuse risk",
               2375: "Docker API exposed = full host control", 445: "SMB exposed to the internet",
               5900: "VNC exposed to the internet"}


def _internetdb(ip: str) -> dict:
    if ":" in ip:
        return {}
    r = fetch(INTERNETDB.format(ip=ip), timeout=12)
    if not r["ok"]:
        return {}
    try:
        d = json.loads(r["text"])
    except Exception:
        return {}
    ports = d.get("ports", []) or []
    return {"ip": ip, "ports": ports, "hostnames": d.get("hostnames", []) or [],
            "cpes": d.get("cpes", []) or [], "vulns": d.get("vulns", []) or [],
            "tags": d.get("tags", []) or [],
            "port_labels": [{"port": p, "name": _PORT_NAMES.get(p, ""), "risky": p in RISKY_PORTS,
                             "why": RISKY_PORTS.get(p, "")} for p in sorted(ports)]}


def passive_ports(ips: list[str], progress=None) -> dict:
    ips = [ip for ip in dict.fromkeys(ips) if ip and ":" not in ip][:12]
    hosts, all_vulns, risky = [], set(), []
    with futures.ThreadPoolExecutor(max_workers=8) as ex:
        for i, d in enumerate(ex.map(_internetdb, ips)):
            if not d:
                continue
            hosts.append(d)
            all_vulns.update(d["vulns"])
            for pl in d["port_labels"]:
                if pl["risky"]:
                    risky.append({"ip": d["ip"], **pl})
            if progress:
                progress(i, len(ips))
    return {"available": bool(hosts), "hosts": hosts, "risky_ports": risky,
            "vuln_ids": sorted(all_vulns)[:200], "vuln_count": len(all_vulns),
            "source": "Shodan InternetDB (passive, public)"}


def infrastructure(subs: dict, primary_ips: list[str], ports: dict) -> dict:
    """Map every IP -> ASN/org/country, and show what else is hosted on them."""
    ip_index = dict(subs.get("ip_index", {}))
    for ip in primary_ips:
        ip_index.setdefault(ip, [])
    hostnames_by_ip = {h["ip"]: h.get("hostnames", []) for h in ports.get("hosts", [])}

    def one(ip):
        info = intel.asn_lookup(ip) or {}
        shared = sorted(set(ip_index.get(ip, []) + hostnames_by_ip.get(ip, [])))
        return {"ip": ip, "asn": info.get("asn", ""), "org": info.get("org", ""),
                "country": info.get("country", ""), "prefix": info.get("prefix", ""),
                "hosts_here": shared[:40], "shared_count": len(shared)}

    ips = list(ip_index)[:20]
    nodes = []
    with futures.ThreadPoolExecutor(max_workers=8) as ex:
        nodes = list(ex.map(one, ips))
    orgs = {}
    countries = {}
    for n in nodes:
        if n["org"]:
            orgs[n["org"]] = orgs.get(n["org"], 0) + 1
        if n["country"]:
            countries[n["country"]] = countries.get(n["country"], 0) + 1
    return {"available": bool(nodes), "ips": nodes, "ip_count": len(nodes),
            "providers": sorted(orgs.items(), key=lambda x: -x[1]),
            "countries": sorted(countries.items(), key=lambda x: -x[1])}


# --------------------------------------------------------------------------- #
# Deep DNS: DNSSEC, BIMI, MTA-STS, DKIM, subdomain-takeover risk
# --------------------------------------------------------------------------- #
def _doh_json(name: str, rtype: str) -> dict:
    try:
        q = f"{intel.DOH}?name={urllib.parse.quote(name)}&type={rtype}&do=1"
        r = fetch(q, timeout=10)
        return json.loads(r["text"]) if r["ok"] else {}
    except Exception:
        return {}


# CNAME targets that are commonly vulnerable to subdomain takeover when unclaimed
TAKEOVER_TARGETS = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "wordpress.com": "WordPress.com", "pantheonsite.io": "Pantheon", "fastly.net": "Fastly",
    "amazonaws.com": "AWS S3/CloudFront", "azurewebsites.net": "Azure", "cloudapp.net": "Azure",
    "cloudapp.azure.com": "Azure", "trafficmanager.net": "Azure", "blob.core.windows.net": "Azure Blob",
    "netlify.app": "Netlify", "netlify.com": "Netlify", "readthedocs.io": "Read the Docs",
    "ghost.io": "Ghost", "surge.sh": "Surge", "bitbucket.io": "Bitbucket", "shopify.com": "Shopify",
    "myshopify.com": "Shopify", "zendesk.com": "Zendesk", "helpscoutdocs.com": "Help Scout",
    "wixsite.com": "Wix", "webflow.io": "Webflow", "unbounce.com": "Unbounce",
    "cargocollective.com": "Cargo", "statuspage.io": "Statuspage", "launchrock.com": "LaunchRock",
}


def dns_deep(domain: str, subs: dict) -> dict:
    domain = _reg(domain)
    out = {}
    # DNSSEC: authenticated-data flag + DS record presence
    a = _doh_json(domain, "A")
    ds = _doh_json(domain, "DS")
    out["dnssec"] = bool(a.get("AD")) or bool(ds.get("Answer"))
    # MTA-STS (email transport security policy)
    mta = doh(f"_mta-sts.{domain}", "TXT")
    out["mta_sts"] = any("v=stsv1" in r["data"].lower() for r in mta)
    tlsrpt = doh(f"_smtp._tls.{domain}", "TXT")
    out["tls_rpt"] = any("v=tlsrptv1" in r["data"].lower() for r in tlsrpt)
    # BIMI (brand logo in inbox)
    bimi = doh(f"default._bimi.{domain}", "TXT")
    out["bimi"] = any("v=bimi1" in r["data"].lower() for r in bimi)
    # extended DKIM selector sweep
    selectors = ("google", "default", "selector1", "selector2", "k1", "k2", "dkim", "mail",
                 "smtp", "mandrill", "mailjet", "sendgrid", "s1", "s2", "zoho", "protonmail",
                 "protonmail2", "amazonses", "everlytickey1", "pm", "fm1")

    def dkim(sel):
        return sel if (doh(f"{sel}._domainkey.{domain}", "TXT") or doh(f"{sel}._domainkey.{domain}", "CNAME")) else None
    with futures.ThreadPoolExecutor(max_workers=10) as ex:
        found = [s for s in ex.map(dkim, selectors) if s]
    out["dkim_selectors"] = found
    out["caa"] = [r["data"] for r in doh(domain, "CAA")]
    # subdomain takeover risk: dangling CNAME to a takeoverable provider
    risks = []
    for s in subs.get("records", []):
        cn = (s.get("cname") or "").lower()
        if not cn:
            continue
        for suffix, provider in TAKEOVER_TARGETS.items():
            if cn.endswith(suffix):
                dangling = not s.get("ips")   # CNAME resolves to a provider but no A record => often unclaimed
                if dangling:
                    risks.append({"subdomain": s["subdomain"], "cname": cn, "provider": provider,
                                  "confidence": "review"})
                break
    out["takeover_risks"] = risks
    return out


# --------------------------------------------------------------------------- #
# Typosquat / look-alike domains (brand protection)
# --------------------------------------------------------------------------- #
_TLDS = ("com", "net", "org", "co", "io", "info", "online", "app", "shop", "xyz", "site")
_SWAPS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}


def _variations(name: str) -> set[str]:
    v = set()
    for i, ch in enumerate(name):
        # omission
        v.add(name[:i] + name[i + 1:])
        # adjacent transposition
        if i + 1 < len(name):
            v.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
        # character swap (leet)
        if ch in _SWAPS:
            v.add(name[:i] + _SWAPS[ch] + name[i + 1:])
        # doubling
        v.add(name[:i] + ch + name[i:])
    v.add(name + "s")
    v.add(name.replace("-", ""))
    if "-" not in name and len(name) > 6:
        v.add(name[: len(name) // 2] + "-" + name[len(name) // 2:])
    v.discard(name)
    return {x for x in v if 2 <= len(x) <= 40}


def typosquats(domain: str, limit: int = 60) -> dict:
    domain = _reg(domain)
    parts = domain.split(".")
    name, tld = parts[0], ".".join(parts[1:])
    cands = set()
    for nm in list(_variations(name))[:40]:
        cands.add(f"{nm}.{tld}")
    for t in _TLDS:
        if t != tld:
            cands.add(f"{name}.{t}")
    cands.discard(domain)
    cands = sorted(cands)[:limit]

    def check(d):
        a = doh(d, "A")
        if not a:
            return None
        mx = doh(d, "MX")
        return {"domain": d, "ips": [r["data"] for r in a][:2], "has_mx": bool(mx),
                "risk": "high" if mx else "medium"}
    found = []
    with futures.ThreadPoolExecutor(max_workers=16) as ex:
        for res in ex.map(check, cands):
            if res:
                found.append(res)
    found.sort(key=lambda x: (x["risk"] != "high", x["domain"]))
    return {"checked": len(cands), "registered": found,
            "count": len(found), "with_mail": sum(1 for f in found if f["has_mx"])}


# --------------------------------------------------------------------------- #
# Reputation: public DNS blocklists for the mail / host IPs
# --------------------------------------------------------------------------- #
DNSBLS = ("zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.net")


def reputation(ips: list[str], mx_ips: list[str] | None = None) -> dict:
    targets = list(dict.fromkeys((mx_ips or []) + ips))[:6]
    listings = []

    def check(ip):
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            return
        rev = ".".join(reversed(ip.split(".")))
        for bl in DNSBLS:
            ans = doh(f"{rev}.{bl}", "A")
            if any(r["data"].startswith("127.") for r in ans):
                listings.append({"ip": ip, "blocklist": bl})
    with futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(check, targets))
    return {"checked_ips": targets, "blocklists_checked": list(DNSBLS),
            "listings": listings, "listed": bool(listings), "clean": not listings}


# --------------------------------------------------------------------------- #
# Owner-research pivots: analytics IDs + favicon hash
# --------------------------------------------------------------------------- #
PIVOT_PATTERNS = {
    "Google Analytics 4": r"\bG-[A-Z0-9]{6,12}\b",
    "Universal Analytics": r"\bUA-\d{4,10}-\d{1,4}\b",
    "Google Tag Manager": r"\bGTM-[A-Z0-9]{5,8}\b",
    "Google AdSense": r"\bca-pub-\d{10,20}\b",
    "Meta Pixel": r"fbq\(['\"]init['\"],\s*['\"](\d{10,20})['\"]",
    "Yandex Metrica": r"ym\((\d{5,10}),",
    "Hotjar": r"hjid[:=]\s*(\d{5,9})",
}


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 — matches Shodan's http.favicon.hash pivot."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xffffffff
    rounded = (length & ~3)
    for i in range(0, rounded, 4):
        k1 = (data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = data[rounded:]
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def _favicon_hash(origin: str, html: str) -> dict:
    import base64
    href = ""
    for lt in re.findall(r"<link\b[^>]*>", html or "", re.I):
        if re.search(r'rel\s*=\s*["\'][^"\']*icon', lt, re.I):
            m = re.search(r'href\s*=\s*["\'](.*?)["\']', lt, re.I)
            if m:
                href = m.group(1)
                break
    url = urllib.parse.urljoin(origin + "/", href or "/favicon.ico")
    r = fetch(url, timeout=10, max_bytes=200000)
    if not r["ok"] or not r.get("body"):
        return {}
    b64 = base64.encodebytes(r["body"])   # Shodan hashes the base64 (with newlines)
    return {"url": url, "shodan_hash": _murmur3_32(b64),
            "shodan_query": f"http.favicon.hash:{_murmur3_32(b64)}"}


def pivots(origin: str, html: str, dns_records: dict | None = None) -> dict:
    ids = []
    for label, pat in PIVOT_PATTERNS.items():
        for m in re.findall(pat, html or ""):
            val = m if isinstance(m, str) else m[0]
            ids.append({"type": label, "id": val})
    # de-dupe
    seen, uniq = set(), []
    for it in ids:
        k = (it["type"], it["id"])
        if k not in seen:
            seen.add(k)
            uniq.append(it)
    fav = _favicon_hash(origin, html)
    # research links so the analyst can pivot to find sibling sites
    links = []
    ga = next((i["id"] for i in uniq if i["type"] in ("Google Analytics 4", "Universal Analytics", "Google AdSense")), "")
    if ga:
        links.append({"label": f"Find sites sharing {ga}", "url": f"https://dnslytics.com/search?q={ga}"})
    if fav.get("shodan_hash") is not None:
        links.append({"label": "Find sites with the same favicon (Shodan)",
                      "url": f"https://www.shodan.io/search?query=http.favicon.hash%3A{fav['shodan_hash']}"})
    return {"identifiers": uniq, "favicon": fav, "research_links": links,
            "count": len(uniq)}


# --------------------------------------------------------------------------- #
# Trust / legitimacy (scam) score
# --------------------------------------------------------------------------- #
def trust_score(report: dict) -> dict:
    score = 100
    reasons = []

    def hit(pts, label):
        nonlocal score
        score -= pts
        reasons.append({"impact": -pts, "reason": label})

    def good(label):
        reasons.append({"impact": 0, "reason": label})

    # domain age
    reg = (report.get("domain", {}) or {}).get("registered")
    age_days = None
    if reg:
        try:
            d = datetime.fromisoformat(reg.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - d).days
        except Exception:
            age_days = None
    if age_days is not None:
        if age_days < 30:
            hit(30, f"Domain is brand new ({age_days} days old)")
        elif age_days < 180:
            hit(18, f"Domain is young ({age_days} days old)")
        elif age_days < 365:
            hit(8, f"Domain under a year old ({age_days} days)")
        else:
            good(f"Established domain ({age_days // 365}+ years old)")

    ssl = report.get("ssl", {})
    if not ssl.get("available"):
        hit(25, "No valid HTTPS certificate")
    elif ssl.get("status") == "expired":
        hit(20, "SSL certificate expired")
    else:
        good("Valid HTTPS certificate")

    em = report.get("email_security", {})
    if em and em.get("spoofable"):
        hit(8, "Email domain is spoofable (no strong SPF/DMARC)")

    rep = report.get("reputation", {})
    if rep.get("listed"):
        hit(30, f"IP appears on {len(rep.get('listings', []))} DNS blocklist(s)")
    elif rep.get("checked_ips"):
        good("Not on common DNS blocklists")

    ports = report.get("passive_ports", {})
    if ports.get("vuln_count"):
        hit(min(12, ports["vuln_count"]), f"{ports['vuln_count']} known CVE(s) on exposed / associated services")
    if ports.get("risky_ports"):
        hit(min(12, len(ports["risky_ports"]) * 4), f"{len(ports['risky_ports'])} risky port(s) exposed")

    contacts = report.get("contacts", {})
    if not (contacts.get("emails") or contacts.get("socials")):
        hit(10, "No public contact info (email or social) found")
    else:
        good("Public contact information present")

    deep = report.get("deep", {})
    if deep.get("exposed_files"):
        hit(15, f"{len(deep['exposed_files'])} sensitive file(s) publicly exposed")
    secrets = report.get("secrets", {})
    if secrets.get("count"):
        hit(min(25, secrets["count"] * 5), f"{secrets['count']} exposed secret(s) in public code")

    tv = report.get("tech_cve", {})
    if tv.get("outdated"):
        hit(min(12, len(tv["outdated"]) * 3), f"{len(tv['outdated'])} outdated component(s) with known issues")

    score = max(0, min(100, score))
    verdict = ("Trusted" if score >= 80 else "Likely OK" if score >= 60
               else "Use caution" if score >= 40 else "High risk")
    return {"score": score, "verdict": verdict,
            "reasons": sorted(reasons, key=lambda r: r["impact"]),
            "age_days": age_days}
