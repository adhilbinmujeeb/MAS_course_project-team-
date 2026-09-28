"""
string_extraction.py
---------------------
Step 3 of Person B's module: pull every string constant embedded in
the app's DEX bytecode and flag ones that look security-relevant:
URLs, raw IP addresses, email addresses, and long base64-looking
blobs (which can indicate embedded secrets, encoded payloads, or
C2 configuration).

This is intentionally a first pass with straightforward regexes.
Malware authors sometimes obfuscate or split strings at runtime to
dodge exactly this kind of static grep, so string extraction is one
signal among several (paired with sensitive_apis.py and, later,
obfuscation heuristics) rather than a standalone verdict.
"""

from __future__ import annotations
import re
from typing import Dict, List

try:
    from .apk_loader import LoadedAPK, load_apk
except ImportError:
    from apk_loader import LoadedAPK, load_apk

# --- Regex patterns -----------------------------------------------------

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
# Base64-looking blobs: long runs of base64 alphabet, optionally padded.
# Length threshold (40+) filters out short strings that just happen to
# be alphanumeric, keeping this focused on plausible encoded payloads.
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

# Obvious placeholder/library noise we don't want cluttering results.
# Androguard pulls in the *entire* string pool, including things like
# XML namespace URIs and standard library boilerplate.
URL_ALLOWLIST_SUBSTRINGS = [
    "schemas.android.com",
    "www.w3.org",
    "xmlpull.org",
    "apache.org/licenses",
]

# Java/DEX type descriptors (e.g. "Landroid/graphics/drawable/Foo;") satisfy
# the base64 character-class regex purely by coincidence, since class and
# package names are alphanumeric. Excluding this specific, well-defined
# pattern removes the majority of false positives without touching real
# base64 data, which never has this shape.
_TYPE_DESCRIPTOR_RE = re.compile(r"^L[A-Za-z0-9_$]+(/[A-Za-z0-9_$]+)+;?$")

# Real base64-encoded binary data draws from a 64-symbol alphabet roughly
# uniformly, so a blob of this length has a very high chance of containing
# several digits. CamelCase identifiers and class names rarely contain any.
# This is a cheap, effective way to separate "looks like base64 but is
# actually a Java identifier" from genuine encoded payloads.
_MIN_DIGITS_FOR_BASE64 = 3


def _is_noise_url(url: str) -> bool:
    return any(noise in url for noise in URL_ALLOWLIST_SUBSTRINGS)


def _looks_like_real_base64(candidate: str) -> bool:
    if _TYPE_DESCRIPTOR_RE.match(candidate):
        return False
    digit_count = sum(c.isdigit() for c in candidate)
    return digit_count >= _MIN_DIGITS_FOR_BASE64


def extract_strings(loaded: LoadedAPK) -> Dict[str, List[str]]:
    """
    Pull all string constants from every DEX in the APK and bucket the
    security-relevant ones. Returns deduplicated, sorted lists so the
    JSON output is stable and diffable between scans.
    """
    urls: set = set()
    ips: set = set()
    emails: set = set()
    base64_blobs: set = set()

    for dex in loaded.dex_files:
        for s in dex.get_strings():
            if not s:
                continue

            for m in URL_RE.finditer(s):
                url = m.group(0)
                if not _is_noise_url(url):
                    urls.add(url)

            for m in IP_RE.finditer(s):
                ip = m.group(0)
                # Filter out version-number-shaped false positives like
                # "4.1.4.0" by requiring each octet to be a valid 0-255 byte
                if all(0 <= int(octet) <= 255 for octet in ip.split(".")):
                    ips.add(ip)

            for m in EMAIL_RE.finditer(s):
                emails.add(m.group(0))

            for m in BASE64_RE.finditer(s):
                candidate = m.group(0)
                if _looks_like_real_base64(candidate):
                    base64_blobs.add(candidate)

    return {
        "urls": sorted(urls),
        "ip_addresses": sorted(ips),
        "emails": sorted(emails),
        "base64_like_blobs": sorted(base64_blobs),
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python string_extraction.py <path_to_apk>")
        sys.exit(1)

    loaded = load_apk(sys.argv[1])
    if loaded:
        findings = extract_strings(loaded)
        # Print counts first for a quick glance, then full detail
        print(f"URLs: {len(findings['urls'])}")
        print(f"IP addresses: {len(findings['ip_addresses'])}")
        print(f"Emails: {len(findings['emails'])}")
        print(f"Base64-like blobs: {len(findings['base64_like_blobs'])}")
        print()
        print(json.dumps(findings, indent=2))
