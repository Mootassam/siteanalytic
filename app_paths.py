"""
Where the app reads bundled files from and writes its data to — the one place
that knows whether we run from source or as the packaged .exe.
"""

from __future__ import annotations

import os
import sys

FROZEN = bool(getattr(sys, "frozen", False))
HERE = os.path.dirname(os.path.abspath(__file__))


def bundle_dir() -> str:
    if FROZEN:
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return HERE


def data_dir() -> str:
    override = os.environ.get("WEBSITE_INTEL_DATA")
    if override:
        d = override
    elif FROZEN:
        docs = os.path.join(os.path.expanduser("~"), "Documents")
        base = docs if os.path.isdir(docs) else (os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"))
        d = os.path.join(base, "Website Intelligence")
    else:
        d = HERE
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def static_dir() -> str:
    return os.path.join(bundle_dir(), "static")
