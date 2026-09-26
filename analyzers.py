"""
Higher-level analyzers built on intel.fetch/dns/ssl: technology fingerprints,
SEO, security headers, cookies, robots, sitemap, a light crawl, asset/link/API
inventories, external domains, web-archive history, and the aggregated profile.
"""

from __future__ import annotations

import concurrent.futures as futures
import json
import re
import urllib.parse
from collections import Counter, defaultdict

from intel import fetch, _host, _registrable, _short

# --------------------------------------------------------------------------- #
# HTML parsing helpers (regex-based; no external parser dependency)
# --------------------------------------------------------------------------- #
TAG = lambda name: re.compile(rf"<{name}\b[^>]*>", re.I)
ATTR = lambda attr: re.compile(rf'{attr}\s*=\s*(["\'])(.*?)\1', re.I | re.S)
META_RE = re.compile(r"<meta\b[^>]*>", re.I)
LINK_TAG = re.compile(r"<link\b[^>]*>", re.I)
SCRIPT_SRC = re.compile(r'<script\b[^>]*\bsrc\s*=\s*(["\'])(.*?)\1', re.I)
SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
HREF = re.compile(r'<a\b[^>]*\bhref\s*=\s*(["\'])(.*?)\1', re.I | re.S)
IMG = re.compile(r'<img\b[^>]*\bsrc\s*=\s*(["\'])(.*?)\1', re.I)
SRCSET = re.compile(r'\bsrcset\s*=\s*(["\'])(.*?)\1', re.I)
SOURCE = re.compile(r'<(?:source|video|audio)\b[^>]*\bsrc\s*=\s*(["\'])(.*?)\1', re.I)


def _attr(tag: str, attr: str) -> str:
    m = ATTR(attr).search(tag)
    return (m.group(2).strip() if m else "")


def _text(html: str, tag: str) -> str:
    m = re.search(rf"<{tag}\b[^>]*>(.*?)</{tag}>", html, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()


def metas(html: str) -> list[dict]:
    out = []
    for m in META_RE.findall(html):
        out.append({
            "name": _attr(m, "name") or _attr(m, "property") or _attr(m, "http-equiv") or _attr(m, "itemprop"),
            "content": _attr(m, "content"),
            "charset": _attr(m, "charset"),
        })
    return out


def meta_val(ms: list[dict], name: str) -> str:
    for m in ms:
        if m["name"].lower() == name.lower():
            return m["content"]
    return ""


# --------------------------------------------------------------------------- #
# Technology fingerprints
# --------------------------------------------------------------------------- #
# Each tech: category + signals. A signal is (where, pattern). "where" is one of
# html, script, header:<name>, cookie, generator, url.
FINGERPRINTS = {
    "React": ("JS framework", [("html", r"data-reactroot|react(?:-dom)?[.@]|_reactListening|__REACT_DEVTOOLS"), ("script", r"react(?:-dom)?(?:\.production|\.development|@|\.min)?\.js")]),
    "Vue.js": ("JS framework", [("html", r"data-v-[0-9a-f]{8}|__vue__|v-cloak"), ("script", r"vue(?:@|\.runtime|\.global|\.min)?\.js")]),
    "Angular": ("JS framework", [("html", r"ng-version|_nghost|_ngcontent|\[ng"), ("script", r"(?:@angular|angular)[.@/]")]),
    "Next.js": ("JS framework", [("html", r"__NEXT_DATA__|/_next/"), ("header:x-powered-by", r"Next\.js")]),
    "Nuxt": ("JS framework", [("html", r"__NUXT__|/_nuxt/")]),
    "Svelte": ("JS framework", [("html", r"svelte-[0-9a-z]{6}"), ("script", r"svelte")]),
    "Gatsby": ("JS framework", [("html", r"___gatsby|/page-data/")]),
    "WordPress": ("CMS", [("html", r"/wp-content/|/wp-includes/"), ("generator", r"WordPress"), ("header:link", r"wp\.me|/wp-json/")]),
    "Shopify": ("E-commerce", [("html", r"cdn\.shopify\.com|Shopify\.theme|/s/files/"), ("header:x-shopid", r".+"), ("header:x-shopify-stage", r".+")]),
    "Magento": ("E-commerce", [("html", r"/static/version\d+/|Magento_|Mage\.Cookies|/skin/frontend/|/mage/cookies"), ("cookie", r"X-Magento")]),
    "WooCommerce": ("E-commerce", [("html", r"/plugins/woocommerce/|wc-block-|woocommerce-page|woocommerce-no-js|/wc-ajax/")]),
    "Wix": ("Website builder", [("html", r"wix\.com|X-Wix|static\.wixstatic"), ("header:x-wix-request-id", r".+")]),
    "Squarespace": ("Website builder", [("html", r"squarespace\.com|Static\.SQUARESPACE|/universal/")]),
    "Webflow": ("Website builder", [("html", r"webflow|data-wf-")]),
    "Drupal": ("CMS", [("html", r"/sites/default/files|Drupal\.settings"), ("generator", r"Drupal"), ("header:x-generator", r"Drupal")]),
    "Joomla": ("CMS", [("generator", r"Joomla"), ("html", r"/media/jui/|option=com_")]),
    "Laravel": ("Backend", [("cookie", r"laravel_session|XSRF-TOKEN"), ("header:set-cookie", r"laravel_session")]),
    "Django": ("Backend", [("cookie", r"csrftoken|sessionid"), ("html", r"csrfmiddlewaretoken")]),
    "Ruby on Rails": ("Backend", [("cookie", r"_rails|_session_id"), ("header:x-powered-by", r"Phusion Passenger")]),
    "Express": ("Backend", [("header:x-powered-by", r"Express")]),
    "ASP.NET": ("Backend", [("header:x-powered-by", r"ASP\.NET"), ("header:x-aspnet-version", r".+"), ("cookie", r"ASP\.NET_SessionId")]),
    "PHP": ("Backend", [("header:x-powered-by", r"PHP/?[\d.]*"), ("cookie", r"PHPSESSID")]),
    "Nginx": ("Web server", [("header:server", r"nginx")]),
    "Apache": ("Web server", [("header:server", r"Apache")]),
    "LiteSpeed": ("Web server", [("header:server", r"LiteSpeed")]),
    "Microsoft IIS": ("Web server", [("header:server", r"IIS|Microsoft-IIS")]),
    "Cloudflare": ("CDN", [("header:server", r"cloudflare"), ("header:cf-ray", r".+")]),
    "Fastly": ("CDN", [("header:x-served-by", r"cache-"), ("header:x-fastly-request-id", r".+"), ("header:via", r"varnish")]),
    "Amazon CloudFront": ("CDN", [("header:x-amz-cf-id", r".+"), ("header:via", r"CloudFront")]),
    "Vercel": ("Hosting", [("header:server", r"Vercel"), ("header:x-vercel-id", r".+")]),
    "Netlify": ("Hosting", [("header:server", r"Netlify"), ("header:x-nf-request-id", r".+")]),
    "GitHub Pages": ("Hosting", [("header:server", r"GitHub\.com")]),
    "Akamai": ("CDN", [("header:x-akamai-transformed", r".+"), ("header:server", r"AkamaiGHost")]),
    "Bootstrap": ("CSS framework", [("html", r"bootstrap(?:\.min)?\.(?:css|js)|class=\"[^\"]*\b(?:col-(?:xs|sm|md|lg)-|navbar-|btn btn-)")]),
    "Tailwind CSS": ("CSS framework", [("html", r"tailwind|class=\"[^\"]*\b(?:flex items-center|text-(?:sm|lg|xl)|bg-(?:white|gray-\d))")]),
    "Font Awesome": ("Icons", [("html", r"font-?awesome|fa-(?:solid|regular|brands)|fontawesome")]),
    "jQuery": ("JS library", [("script", r"jquery[.-]?([\d.]+)?(?:\.min)?\.js"), ("html", r"jQuery")]),
    "Axios": ("JS library", [("script", r"axios(?:\.min)?\.js"), ("html", r"axios")]),
    "GSAP": ("JS library", [("script", r"gsap|TweenMax|TimelineMax")]),
    "Lodash": ("JS library", [("script", r"lodash(?:\.min)?\.js")]),
    "Google Analytics": ("Analytics", [("html", r"google-analytics\.com/analytics\.js|gtag\('config', 'G-|ga\('create'|/g/collect")]),
    "Google Tag Manager": ("Analytics", [("html", r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+")]),
    "Meta Pixel": ("Analytics", [("html", r"connect\.facebook\.net/[^\"']+/fbevents\.js|fbq\('init'")]),
    "Hotjar": ("Analytics", [("html", r"static\.hotjar\.com|hjSetting")]),
    "Segment": ("Analytics", [("html", r"cdn\.segment\.com|analytics\.load")]),
    "Plausible": ("Analytics", [("html", r"plausible\.io/js")]),
    "Stripe": ("Payment", [("html", r"js\.stripe\.com|Stripe\(")]),
    "PayPal": ("Payment", [("html", r"paypal\.com/sdk|paypalobjects\.com|www\.paypal\.com/[^\"']*checkout")]),
    "Klarna": ("Payment", [("html", r"klarna")]),
    "reCAPTCHA": ("Security", [("html", r"google\.com/recaptcha|grecaptcha")]),
    "Cloudflare Turnstile": ("Security", [("html", r"challenges\.cloudflare\.com/turnstile")]),
    "HubSpot": ("Marketing", [("html", r"js\.hs-scripts\.com|hsubspot")]),
    "Intercom": ("Support", [("html", r"widget\.intercom\.io|intercomSettings")]),
}

FINGERPRINTS.update({
    "Preact": ("JS framework", [("script", r"preact(?:\.min)?\.js|/preact@")]),
    "Alpine.js": ("JS framework", [("html", r"x-data=|alpinejs|/alpine(?:\.min)?\.js")]),
    "Ember.js": ("JS framework", [("html", r"ember(?:\.min|\.prod)?\.js|id=\"ember\d")]),
    "Astro": ("JS framework", [("html", r"astro-island|/_astro/")]),
    "Remix": ("JS framework", [("html", r"__remixContext|/build/_shared/")]),
    "Ghost": ("CMS", [("generator", r"Ghost"), ("html", r"/ghost/api/|content/images/")]),
    "Contentful": ("Headless CMS", [("html", r"images\.ctfassets\.net|cdn\.contentful")]),
    "Sanity": ("Headless CMS", [("html", r"cdn\.sanity\.io")]),
    "Strapi": ("Headless CMS", [("header:x-powered-by", r"Strapi"), ("html", r"/uploads/.*strapi")]),
    "Elementor": ("WordPress", [("html", r"elementor-(?:page|widget|frontend)|/elementor/")]),
    "Yoast SEO": ("SEO", [("html", r"Yoast SEO|yoast_wpseo|/wordpress-seo/")]),
    "WPBakery": ("WordPress", [("html", r"js_composer|wpb_")]),
    "BigCommerce": ("E-commerce", [("html", r"cdn\d*\.bigcommerce\.com")]),
    "PrestaShop": ("E-commerce", [("html", r"prestashop|/modules/ps_"), ("generator", r"PrestaShop")]),
    "Google Fonts": ("Fonts", [("html", r"fonts\.googleapis\.com|fonts\.gstatic\.com")]),
    "Google AdSense": ("Advertising", [("html", r"pagead2\.googlesyndication\.com|adsbygoogle")]),
    "Google Maps": ("Maps", [("html", r"maps\.google(?:apis)?\.com|google\.com/maps")]),
    "YouTube": ("Video", [("html", r"youtube\.com/embed|youtube-nocookie\.com|ytimg\.com")]),
    "Vimeo": ("Video", [("html", r"player\.vimeo\.com|vimeocdn\.com")]),
    "Wistia": ("Video", [("html", r"wistia\.(?:com|net)|fast\.wistia")]),
    "Cloudflare Web Analytics": ("Analytics", [("html", r"static\.cloudflareinsights\.com")]),
    "Matomo": ("Analytics", [("html", r"matomo\.js|piwik\.js|_paq\.push")]),
    "Amplitude": ("Analytics", [("html", r"amplitude\.com|cdn\.amplitude")]),
    "Mixpanel": ("Analytics", [("html", r"mixpanel|cdn\.mxpnl\.com")]),
    "Microsoft Clarity": ("Analytics", [("html", r"clarity\.ms|clarity\(\"")]),
    "FullStory": ("Analytics", [("html", r"fullstory\.com|fs\.js|_fs_host")]),
    "LogRocket": ("Analytics", [("html", r"logrocket|lr-in\.io|cdn\.logr-ingest")]),
    "Optimizely": ("A/B testing", [("html", r"optimizely\.com|cdn\.optimizely")]),
    "VWO": ("A/B testing", [("html", r"visualwebsiteoptimizer|dev\.visualwebsiteoptimizer|_vwo")]),
    "Sentry": ("Monitoring", [("html", r"sentry-cdn\.com|@sentry/|Sentry\.init|browser\.sentry")]),
    "New Relic": ("Monitoring", [("html", r"newrelic|nr-data\.net|NREUM")]),
    "Datadog": ("Monitoring", [("html", r"datadoghq|dd-rum|datadog-rum")]),
    "Algolia": ("Site search", [("html", r"algolia|algolianet\.com")]),
    "Zendesk": ("Support", [("html", r"zendesk|zdassets\.com|zopim")]),
    "Drift": ("Support", [("html", r"drift\.com|driftt\.com|drift\.load")]),
    "Crisp": ("Support", [("html", r"crisp\.chat|client\.crisp")]),
    "Tawk.to": ("Support", [("html", r"tawk\.to|embed\.tawk")]),
    "Mailchimp": ("Marketing", [("html", r"mailchimp|list-manage\.com|mc\.us\d")]),
    "Klaviyo": ("Marketing", [("html", r"klaviyo|static\.klaviyo")]),
    "Marketo": ("Marketing", [("html", r"marketo|mktoresp|munchkin\.js")]),
    "Typeform": ("Forms", [("html", r"typeform\.com|embed\.typeform")]),
    "Calendly": ("Scheduling", [("html", r"calendly\.com|assets\.calendly")]),
    "OneTrust": ("Cookie consent", [("html", r"onetrust|cdn\.cookielaw\.org|optanon")]),
    "Cookiebot": ("Cookie consent", [("html", r"cookiebot|consent\.cookiebot")]),
    "hCaptcha": ("Security", [("html", r"hcaptcha\.com")]),
    "Square": ("Payment", [("html", r"squareup\.com|square\.js|web\.squarecdn")]),
    "Braintree": ("Payment", [("html", r"braintreegateway|braintree-api")]),
    "Adyen": ("Payment", [("html", r"adyen\.com|checkoutshopper")]),
    "Razorpay": ("Payment", [("html", r"razorpay|checkout\.razorpay")]),
    "Chart.js": ("JS library", [("script", r"chart(?:\.min)?\.js|chartjs")]),
    "D3.js": ("JS library", [("script", r"d3(?:\.min|\.v\d)?\.js|d3js\.org")]),
    "Three.js": ("JS library", [("script", r"three(?:\.min|\.module)?\.js|threejs")]),
    "Swiper": ("JS library", [("html", r"swiper(?:\.min)?\.(?:js|css)|swiper-slide")]),
    "Lottie": ("JS library", [("script", r"lottie(?:\.min)?\.js|lottiefiles")]),
    "Material UI": ("UI library", [("html", r"MuiButton|mui-|material-ui|css-[a-z0-9]+-Mui")]),
    "Modernizr": ("JS library", [("script", r"modernizr")]),
    "Underscore.js": ("JS library", [("script", r"underscore(?:\.min)?\.js")]),
    "Amazon Web Services": ("Hosting", [("header:server", r"AmazonS3"), ("header:x-amz-request-id", r".+")]),
    "Varnish": ("Cache", [("header:x-varnish", r".+"), ("header:via", r"varnish")]),
})

VERSION_HINTS = {
    "jQuery": r"jquery[.-]?v?([\d]+\.[\d]+(?:\.[\d]+)?)",
    "Bootstrap": r"bootstrap[.-]?v?([\d]+\.[\d]+(?:\.[\d]+)?)",
    "Vue.js": r"vue@?([\d]+\.[\d]+(?:\.[\d]+)?)",
    "React": r"react@?([\d]+\.[\d]+(?:\.[\d]+)?)",
    "Chart.js": r"chart\.js[/@]?v?([\d]+\.[\d]+(?:\.[\d]+)?)",
    "D3.js": r"d3[/@]?v?([\d]+\.[\d]+(?:\.[\d]+)?)",
}


def detect_tech(html: str, headers: dict, cookies_raw: str, scripts: list[str]) -> list[dict]:
    hl = html or ""
    hdr = {k.lower(): v for k, v in (headers or {}).items()}
    generator = ""
    for m in metas(hl):
        if m["name"].lower() == "generator":
            generator = m["content"]
    scripts_joined = " ".join(scripts)
    found = []
    for tech, (cat, signals) in FINGERPRINTS.items():
        evidence = None
        for where, pat in signals:
            rx = re.compile(pat, re.I)
            if where == "html" and rx.search(hl):
                evidence = f"page HTML matches /{pat[:40]}/"
            elif where == "script" and (rx.search(scripts_joined) or rx.search(hl)):
                evidence = f"script matches /{pat[:40]}/"
            elif where == "generator" and rx.search(generator):
                evidence = f'<meta generator="{generator}">'
            elif where == "cookie" and rx.search(cookies_raw or ""):
                evidence = "cookie name matches"
            elif where.startswith("header:"):
                hname = where.split(":", 1)[1]
                val = hdr.get(hname, "")
                if val and rx.search(val):
                    evidence = f"{hname}: {val[:60]}"
            if evidence:
                break
        if evidence:
            item = {"name": tech, "category": cat, "evidence": evidence}
            vh = VERSION_HINTS.get(tech)
            if vh:
                mv = re.search(vh, scripts_joined + " " + hl, re.I)
                if mv:
                    item["version"] = mv.group(1)
            found.append(item)
    return sorted(found, key=lambda t: t["category"])


# --------------------------------------------------------------------------- #
# SEO / security / cookies
# --------------------------------------------------------------------------- #
def seo_analysis(html: str, base_url: str) -> dict:
    ms = metas(html)
    html_tag = TAG("html").search(html)
    lang = _attr(html_tag.group(0), "lang") if html_tag else ""
    headings = {h: [re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", x)).strip()
                    for x in re.findall(rf"<{h}\b[^>]*>(.*?)</{h}>", html, re.I | re.S)][:20]
                for h in ("h1", "h2", "h3")}
    canonical = ""
    favicon = ""
    for lt in LINK_TAG.findall(html):
        rel = _attr(lt, "rel").lower()
        if "canonical" in rel and not canonical:
            canonical = urllib.parse.urljoin(base_url, _attr(lt, "href"))
        if "icon" in rel and not favicon:
            favicon = urllib.parse.urljoin(base_url, _attr(lt, "href"))
    og = {m["name"]: m["content"] for m in ms if m["name"].lower().startswith("og:")}
    tw = {m["name"]: m["content"] for m in ms if m["name"].lower().startswith("twitter:")}
    ld = re.findall(r'<script\b[^>]*type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>', html, re.I | re.S)
    structured = []
    for block in ld[:10]:
        try:
            data = json.loads(block.strip())
            items = data if isinstance(data, list) else [data]
            for it in items:
                if isinstance(it, dict) and it.get("@type"):
                    structured.append(it["@type"] if isinstance(it["@type"], str) else str(it["@type"]))
        except Exception:
            structured.append("(invalid JSON-LD)")
    return {
        "title": _text(html, "title"), "title_length": len(_text(html, "title")),
        "meta_description": meta_val(ms, "description"),
        "description_length": len(meta_val(ms, "description")),
        "canonical": canonical, "robots": meta_val(ms, "robots"),
        "viewport": meta_val(ms, "viewport"), "lang": lang, "favicon": favicon,
        "og": og, "twitter": tw, "headings": headings,
        "h1_count": len(headings["h1"]), "structured_data": structured,
        "charset": next((m["charset"] for m in ms if m["charset"]), ""),
    }


SEC_HEADERS = {
    "strict-transport-security": "HSTS", "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options", "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    "x-xss-protection": "X-XSS-Protection",
}


def security_headers(headers: dict) -> dict:
    hdr = {k.lower(): v for k, v in (headers or {}).items()}
    out = []
    present = 0
    for key, label in SEC_HEADERS.items():
        val = hdr.get(key)
        if val:
            present += 1
        out.append({"header": label, "key": key, "present": bool(val), "value": val or ""})
    grade_pool = ["strict-transport-security", "content-security-policy", "x-frame-options",
                  "x-content-type-options", "referrer-policy", "permissions-policy"]
    score = sum(1 for k in grade_pool if hdr.get(k))
    grade = ["F", "E", "D", "C", "B", "A", "A+"][score]
    return {"headers": out, "present": present, "total": len(SEC_HEADERS), "grade": grade}


def parse_cookies(headers: dict) -> list[dict]:
    """Parse Set-Cookie headers; mask values."""
    raw = []
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            raw.append(v)
    # http.client folds multiple Set-Cookie into one comma-joined string sometimes
    cookies = []
    for line in raw:
        for piece in re.split(r",(?=[^;]+?=)", line):
            parts = [p.strip() for p in piece.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name, value = parts[0].split("=", 1)
            attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:]}
            cookies.append({
                "name": name.strip(),
                "value_masked": ("•" * min(8, len(value)) if value else ""),
                "domain": attrs.get("domain", ""), "path": attrs.get("path", "/"),
                "secure": "secure" in attrs, "httponly": "httponly" in attrs,
                "samesite": attrs.get("samesite", ""), "expires": attrs.get("expires", attrs.get("max-age", "")),
            })
    return cookies


# --------------------------------------------------------------------------- #
# robots.txt / sitemap
# --------------------------------------------------------------------------- #
def robots_txt(origin: str) -> dict:
    r = fetch(origin + "/robots.txt", timeout=10)
    if not r["ok"] or "html" in r["headers"].get("Content-Type", "").lower():
        return {"present": False}
    text = r["text"]
    sitemaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", text)
    groups, cur = [], None
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        if re.match(r"(?i)user-agent:", line):
            cur = {"agent": line.split(":", 1)[1].strip(), "allow": [], "disallow": []}
            groups.append(cur)
        elif cur and re.match(r"(?i)disallow:", line):
            cur["disallow"].append(line.split(":", 1)[1].strip())
        elif cur and re.match(r"(?i)allow:", line):
            cur["allow"].append(line.split(":", 1)[1].strip())
    return {"present": True, "url": r["url"], "content": text[:20000],
            "sitemaps": sitemaps, "groups": groups}


def sitemap_analysis(origin: str, robots_sitemaps: list[str]) -> dict:
    candidates = list(dict.fromkeys(robots_sitemaps + [origin + "/sitemap.xml", origin + "/sitemap_index.xml"]))
    seen, urls, indexes, checked = set(), [], [], []
    queue = candidates[:]
    while queue and len(checked) < 15:
        sm = queue.pop(0)
        if sm in seen:
            continue
        seen.add(sm)
        r = fetch(sm, timeout=12)
        if not r["ok"]:
            continue
        checked.append(sm)
        locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", r["text"], re.I | re.S)
        if "<sitemapindex" in r["text"].lower():
            indexes.append(sm)
            queue.extend(locs[:20])
        else:
            urls.extend(u.strip() for u in locs)
    return {"present": bool(checked), "checked": checked, "is_index": bool(indexes),
            "url_count": len(urls), "urls": urls[:5000]}


# --------------------------------------------------------------------------- #
# Crawl + inventories
# --------------------------------------------------------------------------- #
ASSET_EXT = {
    "image": "png jpg jpeg gif webp avif svg bmp ico".split(),
    "css": ["css"], "js": ["js", "mjs"], "font": "woff woff2 ttf otf eot".split(),
    "video": "mp4 webm mov avi mkv".split(), "audio": "mp3 wav ogg flac m4a".split(),
    "document": "pdf doc docx xls xlsx ppt pptx csv txt".split(),
    "data": "json xml".split(), "archive": "zip rar 7z gz tar".split(),
}
DOC_EXT = set("pdf doc docx xls xlsx ppt pptx csv txt zip rar 7z gz json xml".split())
API_RE = re.compile(r"""["'`](/(?:api|graphql|v\d|rest)/[A-Za-z0-9_\-./]+|https?://[A-Za-z0-9.\-]+/(?:api|graphql)/[A-Za-z0-9_\-./]+)["'`]""", re.I)
WS_RE = re.compile(r"""wss?://[A-Za-z0-9.\-:/_%?=&]+""", re.I)


def _ext(url: str) -> str:
    path = urllib.parse.urlparse(url).path
    return path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""


def _asset_type(url: str) -> str:
    e = _ext(url)
    for t, exts in ASSET_EXT.items():
        if e in exts:
            return t
    return "other"


def extract_links(html: str, base: str):
    out = set()
    for _q, href in HREF.findall(html):
        if href.strip():
            out.add(href.strip())
    return out


def crawl(start_url: str, max_pages: int = 30, max_depth: int = 2, progress=None) -> dict:
    start_host = _registrable(_host(start_url))
    seen, queue = {start_url}, [(start_url, 0)]
    pages, all_links, assets, ext_domains = [], [], {}, Counter()
    apis, ws, public_files = set(), set(), {}
    emails, socials = set(), {}

    def in_scope(u):
        return _registrable(_host(u)) == start_host

    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        r = fetch(url, timeout=12)
        ctype = r["headers"].get("Content-Type", "")
        page = {"url": r.get("url", url), "status": r["status"], "depth": depth,
                "content_type": ctype.split(";")[0], "response_ms": r.get("total_ms"),
                "size": r.get("content_length", 0), "title": ""}
        if r["ok"] and "html" in ctype.lower():
            html = r["text"]
            page["title"] = _text(html, "title")
            # APIs / websockets from html + inline scripts
            for m in API_RE.findall(html):
                apis.add(m)
            for m in WS_RE.findall(html):
                ws.add(m)
            for em in EMAIL_RE.findall(html):
                if _valid_email(em):
                    emails.add(em.lower())
            # assets
            for rx, kind in ((SCRIPT_SRC, "js"), (IMG, "image")):
                for _q, src in rx.findall(html):
                    _add_asset(assets, urllib.parse.urljoin(url, src), url, start_host, ext_domains, kind)
            for lt in LINK_TAG.findall(html):
                href = _attr(lt, "href")
                rel = _attr(lt, "rel").lower()
                if href:
                    full = urllib.parse.urljoin(url, href)
                    kind = "css" if ("stylesheet" in rel or _ext(full) == "css") else _asset_type(full)
                    _add_asset(assets, full, url, start_host, ext_domains, kind)
            for _q, src in SOURCE.findall(html):
                _add_asset(assets, urllib.parse.urljoin(url, src), url, start_host, ext_domains, None)
            # links
            for href in extract_links(html, url):
                if href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
                    all_links.append({"href": href, "type": href.split(":", 1)[0], "source": url})
                    continue
                full = urllib.parse.urljoin(url, href.split("#")[0])
                if not full.startswith("http"):
                    continue
                internal = in_scope(full)
                all_links.append({"href": full, "type": "internal" if internal else "external", "source": url})
                if not internal:
                    ext_domains[_host(full)] += 1
                    plat = _social_platform(full)
                    if plat and plat not in socials:
                        socials[plat] = full
                e = _ext(full)
                if e in DOC_EXT and full not in public_files:
                    public_files[full] = {"url": full, "type": e, "source": url}
                if internal and full not in seen and depth < max_depth:
                    seen.add(full)
                    queue.append((full, depth + 1))
        pages.append(page)
        if progress:
            progress(len(pages), max_pages, page["url"])

    # emails also come from mailto: links (cleaner than scraping text)
    for l in all_links:
        if l["type"] == "mailto":
            em = l["href"].replace("mailto:", "").split("?")[0].strip().lower()
            if _valid_email(em):
                emails.add(em)
    return {
        "pages": pages, "page_count": len(pages),
        "links": all_links, "assets": list(assets.values()),
        "public_files": list(public_files.values()),
        "apis": sorted(apis)[:200], "websockets": sorted(ws)[:50],
        "emails": sorted(emails)[:100],
        "socials": [{"platform": k, "url": v} for k, v in socials.items()],
        "external_domains": [{"domain": d, "count": c, "category": _domain_category(d)}
                             for d, c in ext_domains.most_common(100)],
    }


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
SOCIAL_MAP = {
    "Twitter/X": r"(?:^|\.)(?:twitter|x)\.com$", "Facebook": r"(?:^|\.)facebook\.com$",
    "Instagram": r"(?:^|\.)instagram\.com$", "LinkedIn": r"(?:^|\.)linkedin\.com$",
    "YouTube": r"(?:^|\.)(?:youtube\.com|youtu\.be)$", "GitHub": r"(?:^|\.)github\.com$",
    "TikTok": r"(?:^|\.)tiktok\.com$", "Pinterest": r"(?:^|\.)pinterest\.", "Discord": r"(?:^|\.)discord\.(?:gg|com)$",
    "Telegram": r"(?:^|\.)t\.me$", "WhatsApp": r"(?:^|\.)wa\.me$", "Reddit": r"(?:^|\.)reddit\.com$",
}
_BAD_EMAIL = re.compile(
    r"(@[\d.]+$|@2x|@3x|\.(png|jpg|jpeg|gif|svg|webp|css|js|webp)$|"
    r"example\.(com|org)|sentry\.io$|wixpress|"
    r"@(?:domain|yourdomain|email|yourcompany|company|website|site|host)\.\w+$|"
    r"^(?:you|your|name|user|email|username|firstname|lastname|test|sample|someone|hello|info|example)@(?:domain|example|yourdomain|email|company)\b)",
    re.I)


def _valid_email(em: str) -> bool:
    return bool(em) and len(em) < 100 and not _BAD_EMAIL.search(em)


def _social_platform(url: str) -> str:
    h = _host(url)
    for name, pat in SOCIAL_MAP.items():
        if re.search(pat, h, re.I):
            path = urllib.parse.urlparse(url).path.strip("/")
            if path and path.lower() not in ("share", "sharer", "intent", "sharer.php"):
                return name
    return ""


# --------------------------------------------------------------------------- #
# Email security (SPF / DMARC / MX) from DNS
# --------------------------------------------------------------------------- #
def email_security(host: str, dns_records: dict) -> dict:
    from intel import doh
    domain = _registrable(host)
    txt = [r["data"] for r in dns_records.get("TXT", [])]
    mx = dns_records.get("MX", [])
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), "")
    dmarc_recs = doh(f"_dmarc.{domain}", "TXT")
    dmarc = next((r["data"] for r in dmarc_recs if r["data"].lower().startswith("v=dmarc1")), "")
    # DKIM uses selectors we can't enumerate; probe a few common ones
    dkim = ""
    for sel in ("google", "default", "selector1", "k1", "dkim", "mail"):
        recs = doh(f"{sel}._domainkey.{domain}", "TXT") + doh(f"{sel}._domainkey.{domain}", "CNAME")
        if recs:
            dkim = f"{sel} (found)"
            break
    policy = ""
    m = re.search(r"p=(\w+)", dmarc)
    if m:
        policy = m.group(1)
    score = sum([bool(spf), bool(dmarc), bool(mx), bool(dkim)])
    return {
        "domain": domain, "mx": [r["data"] for r in mx], "has_mx": bool(mx),
        "spf": spf, "has_spf": bool(spf),
        "dmarc": dmarc, "has_dmarc": bool(dmarc), "dmarc_policy": policy,
        "dkim": dkim, "has_dkim": bool(dkim),
        "grade": ["F", "D", "C", "B", "A"][score],
        "spoofable": not (spf and dmarc and policy in ("quarantine", "reject")),
    }


# --------------------------------------------------------------------------- #
# Deep security / best-practice checks (opt-in)
# --------------------------------------------------------------------------- #
EXPOSED_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/config.json", "/wp-config.php.bak",
    "/.htaccess", "/server-status", "/phpinfo.php", "/.DS_Store", "/backup.zip",
    "/composer.json", "/package.json", "/.well-known/security.txt",
]


def deep_checks(origin: str, home: dict, do_exposure: bool = True) -> dict:
    out = {"checks": []}
    hdr = {k.lower(): v for k, v in (home.get("headers") or {}).items()}

    def add(name, ok, detail, severity="warn"):
        out["checks"].append({"name": name, "ok": ok, "detail": detail, "severity": severity})

    # HTTPS redirect
    if origin.startswith("https://"):
        http_origin = "http://" + origin.split("://", 1)[1]
        r = fetch(http_origin, timeout=10, max_redirects=1)
        redirects_https = any(x["to"].startswith("https://") for x in r.get("redirects", [])) or r.get("url", "").startswith("https://")
        add("HTTP → HTTPS redirect", redirects_https,
            "Insecure HTTP redirects to HTTPS" if redirects_https else "HTTP does not force HTTPS", "bad")
    # HSTS preload readiness
    hsts = hdr.get("strict-transport-security", "")
    preload_ready = "preload" in hsts and "includesubdomains" in hsts.lower() and _maxage(hsts) >= 31536000
    add("HSTS preload ready", preload_ready, hsts or "no HSTS header", "warn")
    # security.txt
    st = fetch(origin + "/.well-known/security.txt", timeout=8)
    add("security.txt published", st["ok"] and "text" in st["headers"].get("Content-Type", "").lower(),
        st["url"] if st["ok"] else "not found", "warn")
    # server version disclosure
    server = hdr.get("server", "")
    add("Server version hidden", not re.search(r"\d+\.\d+", server),
        f"Server header reveals version: {server}" if re.search(r"\d+\.\d+", server) else (server or "no Server header"), "warn")
    # powered-by disclosure
    pb = hdr.get("x-powered-by", "")
    add("X-Powered-By hidden", not pb, f"reveals: {pb}" if pb else "not disclosed", "warn")

    # exposed sensitive files
    if do_exposure:
        exposed = []
        for path in EXPOSED_PATHS:
            r = fetch(origin + path, timeout=8, max_bytes=2000)
            ct = r["headers"].get("Content-Type", "").lower()
            body = (r.get("text") or "")[:400]
            looks_real = r["ok"] and "html" not in ct and body.strip() and "<!doctype" not in body.lower()
            if path == "/.well-known/security.txt":
                continue
            if looks_real:
                exposed.append({"path": path, "status": r["status"], "type": ct})
        out["exposed_files"] = exposed
        add("No sensitive files exposed", not exposed,
            f"{len(exposed)} potentially exposed" if exposed else "none of the common paths are public", "bad")
    return out


def _maxage(hsts: str) -> int:
    m = re.search(r"max-age=(\d+)", hsts, re.I)
    return int(m.group(1)) if m else 0


def _add_asset(store, url, source, start_host, ext_domains, kind):
    if not url.startswith("http") or url in store:
        return
    internal = _registrable(_host(url)) == start_host
    if not internal:
        ext_domains[_host(url)] += 1
    store[url] = {"url": url, "type": kind or _asset_type(url), "internal": internal,
                  "source": source, "ext": _ext(url)}


CATEGORIES = {
    "CDN": r"cloudflare|cloudfront|akamai|fastly|jsdelivr|unpkg|cdnjs|bootstrapcdn|gstatic",
    "Analytics": r"google-analytics|googletagmanager|hotjar|segment|mixpanel|amplitude|clarity|plausible|matomo",
    "Advertising": r"doubleclick|googlesyndication|adservice|adnxs|criteo|taboola|outbrain|amazon-adsystem",
    "Fonts": r"fonts\.g(?:oogle|static)|use\.typekit|fontawesome|fonts\.net",
    "Social": r"facebook|twitter|x\.com|instagram|linkedin|youtube|tiktok|pinterest",
    "Payment": r"stripe|paypal|braintree|klarna|square",
    "Video": r"youtube|vimeo|wistia|brightcove",
    "Support": r"intercom|zendesk|drift|crisp|tawk",
}


def _domain_category(domain: str) -> str:
    for cat, pat in CATEGORIES.items():
        if re.search(pat, domain, re.I):
            return cat
    return ""


# --------------------------------------------------------------------------- #
# Web-archive history
# --------------------------------------------------------------------------- #
def archive_history(url: str) -> dict:
    host = _host(url)
    out = {"available": False}
    try:
        r = fetch(f"http://archive.org/wayback/available?url={urllib.parse.quote(host)}", timeout=12)
        data = json.loads(r["text"])
        snap = data.get("archived_snapshots", {}).get("closest")
        if snap:
            out["available"] = True
            out["closest"] = {"timestamp": _fmt_ts(snap.get("timestamp", "")), "url": snap.get("url")}
            out["last"] = _fmt_ts(snap.get("timestamp", ""))  # fallback if CDX is unavailable
    except Exception:
        pass
    try:
        cdx = fetch(f"http://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(host)}"
                    f"&output=json&fl=timestamp&collapse=timestamp:6&limit=-500", timeout=15)
        rows = json.loads(cdx["text"])
        stamps = [r[0] for r in rows[1:]] if len(rows) > 1 else []
        if stamps:
            out["snapshot_count"] = len(stamps)
            out["first"] = _fmt_ts(min(stamps))
            out["last"] = _fmt_ts(max(stamps))
            out["timeline"] = [_fmt_ts(s) for s in sorted(stamps)][-60:]
    except Exception:
        pass
    return out


def _fmt_ts(ts: str) -> str:
    try:
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    except Exception:
        return ts


# --------------------------------------------------------------------------- #
# WordPress deep scan (public endpoints only)
# --------------------------------------------------------------------------- #
def wordpress_scan(origin: str, html: str) -> dict:
    is_wp = bool(re.search(r"/wp-content/|/wp-includes/|/wp-json/", html or "")) \
        or "wordpress" in (html or "").lower()
    if not is_wp:
        return {"is_wordpress": False}
    out = {"is_wordpress": True, "version": "", "users": [], "plugins": [], "theme": "",
           "xmlrpc": None, "rest_users_exposed": False}
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)', html or "", re.I)
    if m:
        out["version"] = m.group(1)
    if not out["version"]:
        rss = fetch(origin + "/feed/", timeout=8)
        mm = re.search(r"generator[^>]*>.*?wordpress[^\d]*([\d.]+)", rss.get("text", ""), re.I | re.S)
        if mm:
            out["version"] = mm.group(1)
    plugins = {}
    for m in re.finditer(r"/wp-content/plugins/([a-z0-9\-_]+)(?:[^\"'>]*?[?&]ver=([\d.]+))?", html or "", re.I):
        name = m.group(1).lower()
        if not plugins.get(name):
            plugins[name] = m.group(2) or ""
    out["plugins"] = [{"name": k, "version": v} for k, v in sorted(plugins.items())][:60]
    mt = re.search(r"/wp-content/themes/([a-z0-9\-_]+)", html or "", re.I)
    if mt:
        out["theme"] = mt.group(1)
    ru = fetch(origin + "/wp-json/wp/v2/users", timeout=8)
    if ru["ok"] and ru["text"].strip().startswith("["):
        try:
            users = json.loads(ru["text"])
            out["users"] = [{"name": u.get("name", ""), "slug": u.get("slug", "")}
                            for u in users if isinstance(u, dict)][:50]
            out["rest_users_exposed"] = bool(out["users"])
        except Exception:
            pass
    if not out["users"]:
        au = fetch(origin + "/?author=1", timeout=8, max_redirects=1)
        for hop in au.get("redirects", []):
            am = re.search(r"/author/([^/]+)/?", hop.get("to", ""))
            if am:
                out["users"] = [{"name": "", "slug": am.group(1)}]
    xr = fetch(origin + "/xmlrpc.php", timeout=8)
    body = (xr.get("text") or "").lower()
    out["xmlrpc"] = ("xml-rpc server accepts post" in body) or xr["status"] == 405 or "methodresponse" in body
    return out


# --------------------------------------------------------------------------- #
# Technology versions -> known-issue advisories (curated, honest)
# --------------------------------------------------------------------------- #
def _vtuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) if v else ()


def _lt(a: str, b: str) -> bool:
    ta, tb = _vtuple(a), _vtuple(b)
    return bool(ta) and ta < tb


CVE_DB = {
    "jQuery": [("3.5.0", "XSS via jQuery.htmlPrefilter (CVE-2020-11022 / CVE-2020-11023)"),
               ("1.9.0", "Multiple legacy XSS/selector issues — very outdated")],
    "Bootstrap": [("3.4.1", "XSS in data-target/tooltip (CVE-2019-8331, CVE-2018-14040..14042)"),
                  ("4.3.1", "XSS in tooltip/popover data-* attributes (CVE-2019-8331)")],
    "Lodash": [("4.17.21", "Prototype pollution / command injection (CVE-2021-23337, CVE-2020-8203)")],
    "AngularJS": [("1.8.0", "Legacy AngularJS 1.x — end of life, multiple XSS sinks")],
    "Angular": [("1.8.0", "AngularJS 1.x is end-of-life")],
    "Moment.js": [("2.29.4", "ReDoS / path traversal in older moment (CVE-2022-24785, CVE-2022-31129)")],
    "Vue.js": [("2.7.0", "Older Vue 2 — check for known template advisories")],
    "Chart.js": [("2.9.4", "Prototype pollution in older Chart.js")],
}


def tech_cve(techs: list[dict]) -> dict:
    outdated = []
    for t in techs:
        v = t.get("version")
        if not v:
            continue
        for fixed, advisory in CVE_DB.get(t["name"], []):
            if _lt(v, fixed):
                outdated.append({"name": t["name"], "version": v, "fixed_in": fixed, "advisory": advisory})
                break
    return {"outdated": outdated, "count": len(outdated),
            "note": "Version detected from public asset URLs; confirm before acting."}


# --------------------------------------------------------------------------- #
# Exposed-secret reporting (masked) + cloud storage + config exposure.
# Reports what a site publicly leaks so the OWNER can fix it. Findings are masked
# and never used, validated or stored elsewhere.
# --------------------------------------------------------------------------- #
SECRET_PATTERNS = [
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("Stripe secret key", r"\bsk_live_[0-9a-zA-Z]{20,40}\b"),
    ("Stripe restricted key", r"\brk_live_[0-9a-zA-Z]{20,40}\b"),
    ("Slack token", r"\bxox[baprs]-[0-9A-Za-z-]{10,60}\b"),
    ("Slack webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("GitHub token", r"\bghp_[0-9A-Za-z]{36}\b"),
    ("Twilio account SID", r"\bAC[0-9a-f]{32}\b"),
    ("SendGrid key", r"\bSG\.[\w\-]{20,30}\.[\w\-]{30,50}\b"),
    ("Mailgun key", r"\bkey-[0-9a-f]{32}\b"),
    ("Private key block", r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\b"),
    ("Firebase database URL", r"https://[a-z0-9\-]+\.firebaseio\.com"),
]
_SECRET_ALLOW = re.compile(r"pk_live_|pk_test_", re.I)
CLOUD_BUCKET = re.compile(
    r"https?://(?:([a-z0-9.\-]+)\.s3[.\-][a-z0-9.\-]*amazonaws\.com|s3[.\-][a-z0-9.\-]*amazonaws\.com/([a-z0-9.\-]+)|"
    r"storage\.googleapis\.com/([a-z0-9.\-_]+)|([a-z0-9\-]+)\.blob\.core\.windows\.net|"
    r"([a-z0-9\-]+)\.firebaseio\.com)", re.I)


def _mask(s: str) -> str:
    s = s.strip()
    if len(s) <= 10:
        return (s[:2] + "•" * max(0, len(s) - 2))
    return s[:4] + "•" * 10 + s[-4:]


def secret_scan(origin: str, html: str, script_urls: list[str], max_scripts: int = 8) -> dict:
    texts = [("page HTML", html or "")]
    internal = [s for s in script_urls if _registrable(_host(s)) == _registrable(_host(origin))]
    for u in internal[:max_scripts]:
        r = fetch(u, timeout=8, max_bytes=1_500_000)
        if r["ok"] and r.get("text"):
            texts.append((u, r["text"]))
    findings, seen = [], set()
    for where, txt in texts:
        for label, pat in SECRET_PATTERNS:
            for m in re.findall(pat, txt):
                val = m if isinstance(m, str) else next((g for g in m if g), "")
                if not val or _SECRET_ALLOW.search(val):
                    continue
                key = (label, val)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({"type": label, "masked": _mask(val), "where": where[:120]})
    return {"count": len(findings), "findings": findings[:60],
            "note": "Reported so the owner can rotate/remove them. Values are masked; never used."}


def cloud_storage(origin: str, html: str, assets: list[dict]) -> dict:
    urls = " ".join([html or ""] + [a.get("url", "") for a in (assets or [])])
    buckets = {}
    for m in CLOUD_BUCKET.finditer(urls):
        full = m.group(0)
        name = next((g for g in m.groups() if g), "")
        base = re.match(r"https?://[^/]+(?:/[a-z0-9.\-_]+)?", full, re.I)
        buckets.setdefault(base.group(0) if base else full, name)
    results = []
    for base, name in list(buckets.items())[:15]:
        prov = ("S3" if "amazonaws" in base else "GCS" if "googleapis" in base
                else "Azure Blob" if "blob.core" in base else "Firebase" if "firebaseio" in base else "cloud")
        listable = False
        try:
            r = fetch(base, timeout=8, max_bytes=4000)
            body = (r.get("text") or "")
            listable = ("ListBucketResult" in body or "<Contents>" in body
                        or (prov == "Firebase" and r["status"] == 200 and body.strip() not in ("", "null")))
        except Exception:
            pass
        results.append({"bucket": name or base, "url": base, "provider": prov, "public_listable": listable})
    return {"count": len(results), "buckets": results, "any_public": any(b["public_listable"] for b in results)}


CONFIG_PATHS = ["/config.js", "/config.json", "/app.config.js", "/env.js", "/.env.js",
                "/appsettings.json", "/firebase-config.js", "/asset-manifest.json", "/graphql"]


def exposed_config(origin: str) -> dict:
    found = []
    for path in CONFIG_PATHS:
        r = fetch(origin + path, timeout=7, max_bytes=4000)
        ct = r["headers"].get("Content-Type", "").lower()
        body = (r.get("text") or "").strip()
        if not r["ok"] or not body:
            continue
        if path == "/graphql":
            if "__schema" in body.lower() or "must provide query" in body.lower() or "introspection" in body.lower():
                found.append({"path": path, "type": "GraphQL endpoint responding",
                              "note": "ensure introspection is disabled in production"})
            continue
        if "<!doctype html" in body.lower() or body.lower().startswith("<html"):
            continue
        interesting = re.search(r"apiKey|api_key|secret|token|password|firebase|database|"
                                r"__INITIAL_STATE__|projectId|authDomain|bucket|endpoint", body, re.I)
        if "json" in ct or "javascript" in ct or interesting:
            found.append({"path": path, "type": ct.split(";")[0] or "config",
                          "note": "public config/state — review for sensitive values" if interesting else "publicly readable"})
    return {"count": len(found), "items": found}
