# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Website Intelligence (onedir, windowed).

Build from this folder:
    pyinstaller packaging/WebsiteIntel.spec --noconfirm

Bundles the Playwright driver (for screenshots/performance) and cryptography
(for SSL certificate parsing). Uses the system Edge, so no Chromium download.
"""

import os
from PyInstaller.utils.hooks import collect_all

REPO = os.path.abspath(os.path.join(SPECPATH, ".."))


def collect_dir(src_rel, dest_rel):
    out = []
    root = os.path.join(REPO, src_rel)
    for base, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            sub = os.path.relpath(base, root)
            dest = dest_rel if sub == "." else os.path.join(dest_rel, sub)
            out.append((full, dest))
    return out


pw_datas, pw_bin, pw_hidden = collect_all("playwright")
cr_datas, cr_bin, cr_hidden = collect_all("cryptography")

datas = pw_datas + cr_datas + collect_dir("static", "static") + collect_dir("assets", "assets")
binaries = pw_bin + cr_bin
hiddenimports = pw_hidden + cr_hidden + [
    "server", "scan", "analyzers", "intel", "app_paths",
    "pystray._win32", "PIL.Image", "PIL.ImageDraw",
]

a = Analysis(
    [os.path.join(REPO, "launcher.py")],
    pathex=[REPO],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "test", "unittest", "pydoc_data"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="Website Intelligence",
    debug=False, strip=False, upx=False,
    console=False,
    icon=os.path.join(REPO, "assets", "icon.ico"),
    version=os.path.join(REPO, "packaging", "version_info.txt"),
)

coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="Website Intelligence")
