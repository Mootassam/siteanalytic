#!/usr/bin/env python3
"""
Website Intelligence Tool - local web server.

    python server.py
Then open http://127.0.0.1:5001

Analyzes only publicly available information about a website. Runs locally.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime

from flask import Flask, abort, jsonify, request, send_file, send_from_directory

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import scan as scanner  # noqa: E402
from app_paths import data_dir, static_dir  # noqa: E402

SCANS_DIR = os.path.join(data_dir(), "scans")
os.makedirs(SCANS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=static_dir())


# --------------------------------------------------------------------------- #
# Scan jobs
# --------------------------------------------------------------------------- #
class Scan:
    def __init__(self, scan_id: str, url: str, opts: dict):
        self.id = scan_id
        self.url = url
        self.opts = opts
        self.status = "queued"     # queued | running | done | error
        self.pct = 0
        self.phase = "queued"
        self.message = ""
        self.error = None
        self.report = None
        self.started = datetime.now().isoformat(timespec="seconds")
        self.finished = None

    def progress(self, pct, phase, msg=""):
        self.pct = pct
        self.phase = phase
        self.message = msg

    def summary(self):
        dna = (self.report or {}).get("dna", {}) if self.report else {}
        return {
            "id": self.id, "url": self.url, "host": (self.report or {}).get("host") or scanner.intel._host(scanner.normalize(self.url)),
            "status": self.status, "pct": self.pct, "phase": self.phase, "message": self.message,
            "error": self.error, "started": self.started, "finished": self.finished,
            "duration": (self.report or {}).get("duration_s"),
            "server": dna.get("server"), "cms": dna.get("cms"), "pages": dna.get("pages_found"),
        }


SCANS: dict[str, Scan] = {}
LOCK = threading.Lock()


def run(sc: Scan):
    sc.status = "running"
    try:
        sc.report = scanner.run_scan(sc.url, sc.opts, progress=sc.progress)
        sc.status = "done"
        _save(sc)
    except Exception as e:
        sc.status = "error"
        sc.error = str(e)
    finally:
        sc.finished = datetime.now().isoformat(timespec="seconds")


def _save(sc: Scan):
    try:
        with open(os.path.join(SCANS_DIR, f"{sc.id}.json"), "w", encoding="utf-8") as f:
            json.dump({"id": sc.id, "url": sc.url, "started": sc.started,
                       "finished": sc.finished, "report": sc.report}, f)
    except OSError:
        pass


def _load_history():
    for name in sorted(os.listdir(SCANS_DIR)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(SCANS_DIR, name), encoding="utf-8") as f:
                d = json.load(f)
            sc = Scan(d["id"], d["url"], {})
            sc.status = "done"
            sc.report = d.get("report")
            sc.started = d.get("started")
            sc.finished = d.get("finished")
            sc.pct = 100
            sc.phase = "done"
            SCANS[sc.id] = sc
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Enter a website URL."}), 400
    opts = {
        "max_pages": max(1, min(200, int(data.get("max_pages", 30) or 30))),
        "max_depth": max(0, min(5, int(data.get("max_depth", 2) or 2))),
        "screenshots": bool(data.get("screenshots", True)),
        "deep": bool(data.get("deep", False)),
    }
    scan_id = uuid.uuid4().hex[:12]
    sc = Scan(scan_id, url, opts)
    with LOCK:
        SCANS[scan_id] = sc
    threading.Thread(target=run, args=(sc,), daemon=True).start()
    return jsonify({"id": scan_id})


@app.route("/api/scan/<scan_id>")
def api_get(scan_id):
    sc = SCANS.get(scan_id)
    if not sc:
        abort(404)
    body = sc.summary()
    if sc.status == "done":
        body["report"] = sc.report
    return jsonify(body)


@app.route("/api/scans")
def api_list():
    with LOCK:
        items = sorted(SCANS.values(), key=lambda s: s.started or "", reverse=True)
    return jsonify([s.summary() for s in items])


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
def api_delete(scan_id):
    with LOCK:
        SCANS.pop(scan_id, None)
    try:
        os.remove(os.path.join(SCANS_DIR, f"{scan_id}.json"))
    except OSError:
        pass
    return jsonify({"ok": True})


@app.route("/api/scan/<scan_id>/export")
def api_export(scan_id):
    sc = SCANS.get(scan_id)
    if not sc or not sc.report:
        abort(404)
    fmt = request.args.get("format", "json")
    host = sc.report.get("host", "site")
    if fmt == "json":
        return send_file(io.BytesIO(json.dumps(sc.report, indent=2, default=str).encode()),
                         mimetype="application/json", as_attachment=True,
                         download_name=f"{host}-intel.json")
    if fmt == "csv":
        return send_file(io.BytesIO(_csv(sc.report).encode()), mimetype="text/csv",
                         as_attachment=True, download_name=f"{host}-intel.csv")
    if fmt == "html":
        return send_file(io.BytesIO(_html_report(sc.report).encode()), mimetype="text/html",
                         as_attachment=True, download_name=f"{host}-intel.html")
    abort(400)


@app.route("/api/compare")
def api_compare():
    a = SCANS.get(request.args.get("a", ""))
    b = SCANS.get(request.args.get("b", ""))
    if not a or not b or not a.report or not b.report:
        abort(404)
    return jsonify(_compare(a.report, b.report))


# --------------------------------------------------------------------------- #
# Export helpers
# --------------------------------------------------------------------------- #
def _csv(report: dict) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Section", "Key", "Value"])
    dna = report.get("dna", {})
    for k, v in dna.items():
        w.writerow(["DNA", k, v])
    for t in report.get("technologies", []):
        w.writerow(["Technology", t["name"], f'{t["category"]} — {t.get("evidence","")}'])
    for p in report.get("crawl", {}).get("pages", []):
        w.writerow(["Page", p["url"], f'{p["status"]} · {p.get("title","")}'])
    for d in report.get("external_domains", []):
        w.writerow(["External domain", d["domain"], f'{d["count"]} refs · {d.get("category","")}'])
    return out.getvalue()


def _compare(a: dict, b: dict) -> dict:
    def pages(r):
        return {p["url"] for p in r.get("crawl", {}).get("pages", [])}
    def techs(r):
        return {t["name"] for t in r.get("technologies", [])}
    pa, pb = pages(a), pages(b)
    ta, tb = techs(a), techs(b)
    return {
        "a": {"url": a["input_url"], "at": a["scanned_at"]},
        "b": {"url": b["input_url"], "at": b["scanned_at"]},
        "pages_added": sorted(pb - pa), "pages_removed": sorted(pa - pb),
        "tech_added": sorted(tb - ta), "tech_removed": sorted(ta - tb),
        "ssl_changed": a.get("ssl", {}).get("valid_to") != b.get("ssl", {}).get("valid_to"),
        "security_a": a.get("security_headers", {}).get("grade"),
        "security_b": b.get("security_headers", {}).get("grade"),
        "server_a": a.get("http", {}).get("server"), "server_b": b.get("http", {}).get("server"),
    }


def _html_report(report: dict) -> str:
    dna = report.get("dna", {})
    rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in dna.items())
    techs = "".join(f"<li><b>{t['name']}</b> — {t['category']}</li>" for t in report.get("technologies", []))
    return f"""<!doctype html><meta charset="utf-8"><title>Intel — {report.get('host')}</title>
<style>body{{font:14px system-ui;margin:40px;max-width:900px}}table{{border-collapse:collapse;width:100%}}
td{{border:1px solid #ccc;padding:6px 10px}}h1{{font-size:22px}}</style>
<h1>Website Intelligence — {report.get('host')}</h1>
<p>Scanned {report.get('scanned_at')}</p>
<h2>Website DNA</h2><table>{rows}</table>
<h2>Technologies</h2><ul>{techs}</ul>"""


if __name__ == "__main__":
    _load_history()
    port = int(os.environ.get("PORT", "5001"))
    print(f"\n  Website Intelligence  ->  http://127.0.0.1:{port}\n")
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False)
