"""
Website Intelligence engine.

Given a URL, it gathers a full technical profile from PUBLIC information only:
HTTP, headers, DNS, RDAP/WHOIS, IP/ASN, SSL/TLS, technology fingerprints, SEO,
security headers, cookies, robots.txt, sitemap, a light crawl (pages / links /
assets / public files / API references / external domains), web-archive history,
and an aggregated "Website DNA" summary.

Everything is defensive: any single probe can fail without sinking the scan,
and each phase reports progress so the UI can stream it.

Only analyzes publicly reachable data about a site. No logins, no exploits.
"""

from __future__ import annotations

import concurrent.futures as futures
import gzip
import io
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes  # noqa: F401
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0 Safari/537.36 WebsiteIntel/1.0")
DEFAULT_TIMEOUT = 15
DOH = "https://dns.google/resolve"


# --------------------------------------------------------------------------- #
# Low-level HTTP
# --------------------------------------------------------------------------- #
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # we follow redirects manually to capture the chain


_opener = urllib.request.build_opener(_NoRedirect)


def _decompress(body: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower()
    try:
        if enc == "gzip":
            return gzip.decompress(body)
        if enc == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        pass
    return body


def fetch(url: str, method: str = "GET", timeout: int = DEFAULT_TIMEOUT,
          max_redirects: int = 10, want_body: bool = True, max_bytes: int = 5_000_000) -> dict:
    """One HTTP call, following redirects manually. Never raises."""
    redirects: list[dict] = []
    current = url
    t0 = time.perf_counter()
    ttfb = None
    for _hop in range(max_redirects + 1):
        req = urllib.request.Request(current, method=method, headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.9",
        })
        try:
            hop_start = time.perf_counter()
            resp = _opener.open(req, timeout=timeout)
            status = resp.getcode()
            headers = resp.headers
            raw = b""
        except urllib.error.HTTPError as e:
            status = e.code
            headers = e.headers
            resp = e  # HTTPError is a readable response too
        except Exception as e:
            return {"ok": False, "error": _short(e), "url": current,
                    "redirects": redirects, "status": 0, "headers": {}, "total_ms": None}
        if ttfb is None:
            ttfb = round((time.perf_counter() - hop_start) * 1000)

        if status in (301, 302, 303, 307, 308) and headers.get("Location"):
            loc = urllib.parse.urljoin(current, headers.get("Location"))
            redirects.append({"from": current, "to": loc, "status": status})
            try:
                resp.read()
                resp.close()
            except Exception:
                pass
            current = loc
            continue

        body = b""
        if want_body:
            try:
                body = resp.read(max_bytes)
            except Exception:
                body = b""
        try:
            resp.close()
        except Exception:
            pass
        enc = headers.get("Content-Encoding", "")
        decoded = _decompress(body, enc)
        text = ""
        if want_body:
            charset = "utf-8"
            m = re.search(r"charset=([\w-]+)", headers.get("Content-Type", ""), re.I)
            if m:
                charset = m.group(1)
            try:
                text = decoded.decode(charset, "replace")
            except LookupError:
                text = decoded.decode("utf-8", "replace")
        version = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(getattr(resp, "version", 11), "HTTP/1.1")
        return {
            "ok": status < 400,
            "status": status,
            "url": current,
            "redirects": redirects,
            "headers": {k: v for k, v in headers.items()},
            "raw_len": len(body),
            "content_length": len(decoded),
            "content_encoding": enc,
            "body": decoded if want_body else b"",
            "text": text,
            "ttfb_ms": ttfb,
            "total_ms": round((time.perf_counter() - t0) * 1000),
            "http_version": version,
        }
    return {"ok": False, "error": "too many redirects", "url": current,
            "redirects": redirects, "status": 0, "headers": {}, "total_ms": None}


def _short(e) -> str:
    return str(e).strip().splitlines()[0][:200] if str(e).strip() else e.__class__.__name__


def _host(url: str) -> str:
    return (urllib.parse.urlparse(url).hostname or "").lower()


def _registrable(host: str) -> str:
    """Rough eTLD+1 (good enough without the full public-suffix list)."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two = {"co", "com", "org", "net", "gov", "edu", "ac", "gob"}
    if parts[-2] in two and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# --------------------------------------------------------------------------- #
# DNS over HTTPS
# --------------------------------------------------------------------------- #
def doh(name: str, rtype: str) -> list[dict]:
    try:
        q = f"{DOH}?name={urllib.parse.quote(name)}&type={rtype}"
        r = fetch(q, timeout=10)
        if not r["ok"]:
            return []
        data = json.loads(r["text"])
        out = []
        for a in data.get("Answer", []):
            out.append({"data": a.get("data", "").strip('"'), "ttl": a.get("TTL"), "type": a.get("type")})
        return out
    except Exception:
        return []


def dns_records(host: str) -> dict:
    types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"]
    out = {}
    with futures.ThreadPoolExecutor(max_workers=8) as ex:
        res = {t: ex.submit(doh, host, t) for t in types}
        for t, f in res.items():
            try:
                out[t] = f.result(timeout=12)
            except Exception:
                out[t] = []
    ttls = [r["ttl"] for recs in out.values() for r in recs if r.get("ttl")]
    return {"records": out, "min_ttl": min(ttls) if ttls else None}


def asn_lookup(ip: str) -> dict:
    """ASN via Team Cymru's DNS service (over DoH). No API key needed."""
    try:
        if ":" in ip:
            return {}
        rev = ".".join(reversed(ip.split(".")))
        txt = doh(f"{rev}.origin.asn.cymru.com", "TXT")
        if not txt:
            return {}
        parts = [p.strip() for p in txt[0]["data"].split("|")]
        asn = parts[0].split()[0] if parts else ""
        info = {"asn": f"AS{asn}", "prefix": parts[1] if len(parts) > 1 else "",
                "country": parts[2] if len(parts) > 2 else "", "registry": parts[3] if len(parts) > 3 else ""}
        name = doh(f"AS{asn}.asn.cymru.com", "TXT")
        if name:
            np = [p.strip() for p in name[0]["data"].split("|")]
            info["org"] = np[-1] if np else ""
        return info
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# SSL / TLS
# --------------------------------------------------------------------------- #
def ssl_info(host: str, port: int = 443, timeout: int = DEFAULT_TIMEOUT) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                tls_version = ss.version()
                cipher = ss.cipher()
    except Exception as e:
        return {"available": False, "error": _short(e)}

    out = {"available": True, "tls_version": tls_version,
           "cipher": cipher[0] if cipher else None}
    if _HAVE_CRYPTO and der:
        try:
            cert = x509.load_der_x509_certificate(der)
            out["issuer"] = _name(cert.issuer, prefer_org=True)
            out["subject"] = _name(cert.subject, prefer_org=False)
            nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
            na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
            out["valid_from"] = nb.isoformat()
            out["valid_to"] = na.isoformat()
            out["days_remaining"] = (na - datetime.now(timezone.utc)).days
            out["signature_algorithm"] = cert.signature_algorithm_oid._name
            out["serial"] = format(cert.serial_number, "x")
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                out["sans"] = san.value.get_values_for_type(x509.DNSName)
            except Exception:
                out["sans"] = []
            out["expired"] = out["days_remaining"] < 0
            out["status"] = "expired" if out["expired"] else ("expiring soon" if out["days_remaining"] < 21 else "valid")
        except Exception as e:
            out["parse_error"] = _short(e)
    return out


def _name(name, prefer_org: bool = False) -> str:
    try:
        cn = [a.value for a in name if a.oid._name == "commonName"]
        o = [a.value for a in name if a.oid._name == "organizationName"]
        # issuer reads better by organization ("Let's Encrypt"); subject by CN
        order = (o, cn) if prefer_org else (cn, o)
        for choice in order:
            if choice:
                label = choice[0]
                if prefer_org and cn and cn[0] != label:
                    label = f"{label} ({cn[0]})"
                return label
        return ", ".join(f"{a.oid._name}={a.value}" for a in name)
    except Exception:
        return str(name)
