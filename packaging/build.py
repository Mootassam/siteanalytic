"""
Build Website Intelligence into a Windows installer.

    python packaging/build.py

icon -> PyInstaller (onedir exe) -> Inno Setup (installer). Output in installer_output/.
Needs: pip install pyinstaller pillow pystray cryptography ; and Inno Setup 6.
"""

import os
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(REPO, "packaging")


def find_iscc():
    for cand in (
        shutil.which("iscc"), shutil.which("ISCC"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "Inno Setup 6", "ISCC.exe"),
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ):
        if cand and os.path.isfile(cand):
            return cand
    return None


def run(cmd):
    print("\n>>>", " ".join(f'"{c}"' if " " in c else c for c in cmd))
    subprocess.run(cmd, check=True, cwd=REPO)


def main():
    run([sys.executable, os.path.join(PKG, "make_icon.py")])
    for d in ("build", os.path.join("dist", "Website Intelligence")):
        p = os.path.join(REPO, d)
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
    run([sys.executable, "-m", "PyInstaller", os.path.join(PKG, "WebsiteIntel.spec"), "--noconfirm", "--clean"])

    exe = os.path.join(REPO, "dist", "Website Intelligence", "Website Intelligence.exe")
    if not os.path.isfile(exe):
        sys.exit("PyInstaller did not produce the expected exe: " + exe)
    print("built:", exe)

    iscc = find_iscc()
    if not iscc:
        print("\nInno Setup not found. Standalone app is ready in:", os.path.dirname(exe))
        return
    run([iscc, os.path.join(PKG, "installer.iss")])
    out = os.path.join(REPO, "installer_output")
    print("\nDONE. Installer(s) in installer_output/:")
    for f in (os.listdir(out) if os.path.isdir(out) else []):
        print("   ", f)


if __name__ == "__main__":
    main()
