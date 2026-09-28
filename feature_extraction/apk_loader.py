"""
apk_loader.py
--------------
Step 1 of Person B's module: load an APK with Androguard and expose
the three core objects everything else builds on:

    apk       -> androguard.core.apk.APK            (manifest/resources)
    dex_files -> list[androguard.core.dex.DEX]       (raw dex objects)
    analysis  -> androguard.core.analysis.analysis.Analysis
                 (cross-referenced call graph — this is what lets us
                  ask "who calls sendTextMessage?" etc.)

Everything downstream (sensitive API detection, string extraction,
obfuscation heuristics) is built on top of `analysis` and `dex_files`,
so getting this loading reliably — including handling corrupt/invalid
APKs gracefully — is the foundation.
"""

from __future__ import annotations
import hashlib
import logging
import os
import sys
from dataclasses import dataclass
from typing import Optional

# Androguard is very chatty (DEBUG-level xref logging) by default via loguru.
# Silence it so our own output isn't drowned out; callers can re-enable
# by removing this if they need low-level debugging.
try:
    from loguru import logger as _ag_logger
    _ag_logger.remove()
    _ag_logger.add(sys.stderr, level="WARNING")
except ImportError:
    pass

from androguard.misc import AnalyzeAPK


@dataclass
class LoadedAPK:
    path: str
    sha256: str
    apk: object          # androguard APK object
    dex_files: list       # list of DEX objects
    analysis: object      # androguard Analysis object


def sha256_of_file(path: str) -> str:
    """Hash the APK so results can be keyed/deduped by content, not filename."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_apk(path: str) -> Optional[LoadedAPK]:
    """
    Load and analyze an APK file. Returns None (and prints why) if the
    file doesn't exist or Androguard can't parse it as a valid APK —
    this matters because Person A's ingestion module should catch most
    bad files, but B's module needs to fail gracefully too rather than
    crashing the whole pipeline on one bad sample.
    """
    if not os.path.isfile(path):
        print(f"[apk_loader] File not found: {path}")
        return None

    try:
        apk, dex_files, analysis = AnalyzeAPK(path)
    except Exception as e:
        print(f"[apk_loader] Failed to parse APK '{path}': {e}")
        return None

    return LoadedAPK(
        path=path,
        sha256=sha256_of_file(path),
        apk=apk,
        dex_files=dex_files,
        analysis=analysis,
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python apk_loader.py <path_to_apk>")
        sys.exit(1)

    loaded = load_apk(sys.argv[1])
    if loaded:
        print(f"Loaded: {loaded.path}")
        print(f"SHA256: {loaded.sha256}")
        print(f"Package name: {loaded.apk.get_package()}")
        print(f"Number of DEX files: {len(loaded.dex_files)}")
        print(f"Number of classes analyzed: {len(list(loaded.analysis.get_classes()))}")
