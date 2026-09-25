"""
Desktop launcher for Website Intelligence.

Starts the local server, opens the interface in the browser, and lives in the
system tray (Open / Open scans folder / Quit). Entry point for the .exe.

Analyzes only publicly available information about a website. Runs locally.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

if getattr(sys, "frozen", False):
    _BASE = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from app_paths import bundle_dir, data_dir  # noqa: E402

PREFERRED_PORT = int(os.environ.get("PORT", "5001"))
MARKER = b"Website Intelligence"


def _instance_url(port: int) -> str | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1.5) as r:
            if MARKER in r.read(4096):
                return f"http://127.0.0.1:{port}/"
    except Exception:
        pass
    return None


def _free_port(preferred: int) -> int:
    for candidate in (preferred, 0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", candidate))
            port = s.getsockname()[1]
            s.close()
            return port
        except OSError:
            continue
    return preferred


def _wait_ready(port: int, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1.5)
            return True
        except Exception:
            time.sleep(0.3)
    return False


def _open_scans_folder():
    d = os.path.join(data_dir(), "scans")
    os.makedirs(d, exist_ok=True)
    try:
        os.startfile(d)  # noqa: S606
    except Exception:
        webbrowser.open("file:///" + d.replace("\\", "/"))


def _load_icon():
    from PIL import Image
    for name in ("assets/icon.ico", "assets/icon.png"):
        path = os.path.join(bundle_dir(), *name.split("/"))
        if os.path.isfile(path):
            try:
                return Image.open(path)
            except Exception:
                pass
    from PIL import ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((4, 4, 60, 60), radius=14, fill=(108, 140, 255, 255))
    d.ellipse((20, 20, 44, 44), outline=(255, 255, 255, 255), width=3)
    return img


def _run_tray(url: str):
    try:
        import pystray
    except Exception:
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            os._exit(0)
        return

    def do_open(icon=None, item=None):
        webbrowser.open(url)

    def do_folder(icon=None, item=None):
        _open_scans_folder()

    def do_quit(icon=None, item=None):
        try:
            icon.stop()
        except Exception:
            pass
        os._exit(0)

    menu = pystray.Menu(
        pystray.MenuItem("Open Website Intelligence", do_open, default=True),
        pystray.MenuItem("Open scans folder", do_folder),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", do_quit),
    )
    pystray.Icon("WebsiteIntel", _load_icon(), "Website Intelligence", menu).run()


def main():
    existing = _instance_url(PREFERRED_PORT)
    if existing:
        webbrowser.open(existing)
        return

    import server as webapp

    port = _free_port(PREFERRED_PORT)
    url = f"http://127.0.0.1:{port}/"
    try:
        webapp._load_history()
    except Exception:
        pass
    threading.Thread(
        target=lambda: webapp.app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False),
        daemon=True,
    ).start()
    if _wait_ready(port):
        webbrowser.open(url)
    _run_tray(url)


if __name__ == "__main__":
    main()
