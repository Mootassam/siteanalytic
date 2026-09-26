# Website Intelligence Tool

Enter a website URL and get a complete technical intelligence report — all from
**publicly available information**, in one good-looking page.

> Analyzes only public data about a site (like BuiltWith + SecurityHeaders + DNS
> tools combined). No logins, no exploits.

## Install as a Windows app (easiest)

Run **`installer_output/WebsiteIntelligence-Setup-1.0.0.exe`**. It installs
per-user (no admin), adds Start-menu and optional desktop shortcuts, shows a
Terms-of-Use screen, and registers an uninstaller. Launch **Website
Intelligence** and it opens in your browser with a tray icon (right-click for
Open, Open scans folder, Quit). Uses the system Edge, so the download stays
small; your scans are saved in **Documents\Website Intelligence\scans**.

Build the installer yourself with **`Build Installer.bat`** (or
`python packaging/build.py`) — needs Inno Setup 6 plus `pyinstaller pillow
pystray cryptography`.

## Run from source

```bash
cd website-intel
pip install -r requirements.txt
playwright install chromium   # optional — screenshots use system Edge if present
python server.py
```

Then open <http://127.0.0.1:5001> (or double-click **`Start.bat`** on Windows).

## What it reports

- **Intelligence Score (0–100)** — a weighted grade from security, performance, SEO and best practices, with a ring gauge and subscore bars.
- **Findings & recommendations** — a prioritized list of issues (critical / warning / info) from every check, so it's actionable, not just data.
- **Website DNA** — one-glance profile (IP, ASN, server, CDN, CMS, frameworks, SSL, email grade, security grade, page weight, pages, assets…).
- **Performance & sustainability** — real in-browser metrics: load time, TTFB, page weight, request count, DOM nodes, transfer-by-type, and an estimated **CO₂ per visit**.
- **Email security** — SPF, DKIM, DMARC and MX with an anti-spoofing grade (is the domain spoofable?).
- **Contacts** — public email addresses and social-media profiles (Twitter/X, LinkedIn, Instagram, YouTube, GitHub, TikTok…) discovered on the site.
- **Deep security checks** (opt-in) — HTTP→HTTPS redirect, HSTS preload readiness, `security.txt`, server/version disclosure, and public exposure of sensitive files (`.env`, `.git`, backups…).
- ~90 **technology fingerprints** with evidence.
- **Domain & DNS** — RDAP/WHOIS (registrar, dates, status, nameservers), A/AAAA/CNAME/MX/NS/TXT/CAA/SOA, IP + ASN.
- **SSL/TLS** — issuer, subject, validity, days remaining, SANs, TLS version, cipher, signature.
- **HTTP** — status, redirect chain, timing/TTFB, version, headers, compression, cookies (values masked).
- **Technologies** — frameworks, CMS, e-commerce, servers, CDNs, hosting, CSS/JS libraries, analytics, payments — **with evidence** for each.
- **SEO** — title, meta, canonical, robots, viewport, Open Graph, Twitter cards, headings, structured data.
- **Security headers** — HSTS, CSP, X-Frame-Options, etc., with a grade.
- **Crawler** — discovered pages (status, title, size, timing, depth).
- **Assets / JavaScript / APIs / Links / Public files / External domains** — full inventories.
- **Sitemap & robots.txt** — parsed, and compared against the crawl.
- **Screenshots** — desktop (full page) + mobile.
- **History** — Internet Archive snapshot count, first/last seen, timeline.
- **Export** — JSON, CSV, HTML. **Scan history** and **compare two scans**.

## Deep intelligence (opt-in — passive OSINT)

Tick **🛰️ Deep intelligence** to add a full reconnaissance layer, all from public
sources (Certificate Transparency, DNS-over-HTTPS, Shodan's free InternetDB, public
DNS blocklists, and what the site itself serves). Nothing authenticates, brute-forces
or exploits. Where an exposure is found it is **reported masked**, so the owner can fix
it — never used or stored.

- **Subdomain discovery** — from CT logs (crt.sh) + DNS, resolved and live-checked, with staging / internal / mail / service classification.
- **Relationship map** — an interactive OSINT graph linking the domain → subdomains → IPs → hosting → tracking identifiers → social → look-alike domains.
- **Infrastructure map** — every IP → ASN / org / country, plus what else is hosted on each IP (shared-host view).
- **Ports & known CVEs** — passive, from Shodan InternetDB: open ports, software (CPEs) and public CVEs per IP (no active scanning), with risky-port highlighting.
- **Certificate history** — every SSL certificate ever issued (crt.sh), issuers and timeline.
- **Deep DNS** — DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA, an extended DKIM-selector sweep, and **subdomain-takeover** (dangling-CNAME) detection.
- **Reputation** — the domain/mail IPs checked against public DNS blocklists.
- **Look-alike domains** — generated typosquats resolved live; flags ones that can send email (phishing risk).
- **Owner-research pivots** — GA / GTM / AdSense / Pixel IDs + a Shodan-style favicon hash, with links to find sibling sites.
- **WordPress deep scan** — version, theme, plugins (with versions), public author accounts (REST), XML-RPC status.
- **Technology versions → advisories** — outdated components matched to known-issue advisories/CVEs.
- **Exposure reporting** — secrets in public code (masked), publicly listable cloud buckets, exposed config/state — reported for remediation.
- **Trust & risk score** — a weighted legitimacy rating (domain age, HTTPS, reputation, exposures, CVEs, contactability) for spotting risky or fraudulent sites.

Deep intelligence is slower (it queries several public services) and every check is
isolated: any one can fail without affecting the rest of the report.

## How it's built

- `intel.py` — low-level probes: HTTP (with redirect chain + timing), DNS-over-HTTPS, ASN (Team Cymru), SSL/TLS (via `cryptography`).
- `analyzers.py` — technology fingerprints, SEO, security headers, cookies, robots/sitemap, crawler, inventories, web-archive history, plus WordPress scan, version→CVE advisories, and exposure reporting (secrets/cloud/config).
- `recon.py` — deep intelligence: CT-log subdomains & certificate history, Shodan InternetDB ports/CVEs, infrastructure map, deep DNS + subdomain-takeover, typosquats, reputation, owner pivots (incl. favicon hash), trust score.
- `scan.py` — runs every phase, streams progress, assembles the report + Website DNA, captures screenshots (Playwright).
- `server.py` — Flask API (scan jobs, history, compare, export).
- `static/index.html` — the single-page UI.

All network calls are defensive: any single probe can fail without sinking the
scan. Data sources used: Google DNS-over-HTTPS, rdap.org, Team Cymru (ASN),
Internet Archive, Certificate Transparency (crt.sh), Shodan InternetDB, and public
DNS blocklists — all free and public, no API keys required.

Later this can be packaged as a Windows `.exe` the same way as the site cloner.
