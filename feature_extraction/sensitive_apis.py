"""
sensitive_apis.py
------------------
Step 2 of Person B's module: scan the loaded APK's method analysis for
calls into a curated list of security-relevant Android APIs, grouped
into categories that match common malware behaviors (SMS fraud,
device fingerprinting, dynamic code loading, reflection abuse,
shell/process execution, crypto misuse).

This uses Androguard's cross-reference (xref) data: for every method
in the app's own code, we check its list of called methods (xref_to)
and see if any match our curated patterns. This is the core signal
that later feeds the rule-based scoring engine (Person C).
"""

from __future__ import annotations
from collections import defaultdict
from typing import Dict, List

try:
    from .apk_loader import LoadedAPK, load_apk
except ImportError:
    from apk_loader import LoadedAPK, load_apk

# Curated sensitive API patterns, grouped by category.
# Matching is substring-based against "ClassName;methodname" style strings
# Androguard exposes, e.g. "Landroid/telephony/SmsManager; sendTextMessage"
SENSITIVE_APIS: Dict[str, List[str]] = {
    "sms_fraud": [
        "SmsManager; sendTextMessage",
        "SmsManager; sendMultipartTextMessage",
        "SmsManager; sendDataMessage",
    ],
    "device_fingerprinting": [
        "TelephonyManager; getDeviceId",
        "TelephonyManager; getSubscriberId",
        "TelephonyManager; getSimSerialNumber",
        "TelephonyManager; getLine1Number",
        "Settings$Secure; getString",  # often used to read ANDROID_ID
    ],
    "dynamic_code_loading": [
        "DexClassLoader;",
        "PathClassLoader;",
        "InMemoryDexClassLoader;",
        "ClassLoader; loadClass",
    ],
    "reflection": [
        "Method; invoke",
        "Class; forName",
        "Class; getMethod",
        "Class; getDeclaredMethod",
    ],
    "shell_and_process_exec": [
        "Runtime; exec",
        "ProcessBuilder;",
    ],
    "crypto_usage": [
        "Cipher; getInstance",
        "SecretKeySpec;",
        "MessageDigest; getInstance",
    ],
    "contacts_and_pii": [
        "ContactsContract",
        "AccountManager; getAccounts",
    ],
    "location": [
        "LocationManager; getLastKnownLocation",
        "LocationManager; requestLocationUpdates",
    ],
}


def scan_sensitive_apis(loaded: LoadedAPK) -> Dict[str, dict]:
    """
    Walk every method defined in the app's own code and check its
    outgoing calls (xref_to) against the SENSITIVE_APIS patterns.

    Returns a dict like:
        {
          "sms_fraud": {"count": 2, "callers": ["Lcom/example/Foo; bar"]},
          ...
        }
    Only categories with at least one hit are included, keeping the
    output JSON compact for the downstream scoring engine.
    """
    results: Dict[str, dict] = defaultdict(lambda: {"count": 0, "callers": set(), "matches": {}})

    for cls in loaded.analysis.get_classes():
        # Skip library/external classes — we only care about the app's own code
        if cls.is_external():
            continue
        for method in cls.get_methods():
            caller_name = f"{cls.name.rstrip(';')}; {method.name}"
            for _, call, _ in method.get_xref_to():
                call_str = f"{call.class_name.rstrip(';')}; {call.name}"
                for category, patterns in SENSITIVE_APIS.items():
                    if any(p in call_str for p in patterns):
                        results[category]["count"] += 1
                        results[category]["callers"].add(caller_name)
                        match = results[category]["matches"].setdefault(call_str, {"count": 0, "callers": set()})
                        match["count"] += 1
                        match["callers"].add(caller_name)

    # Convert sets to sorted lists for clean JSON serialization
    return {
        cat: {"count": v["count"], "callers": sorted(v["callers"]),
              "matches": [{"api": api, "count": hit["count"], "callers": sorted(hit["callers"])}
                          for api, hit in sorted(v["matches"].items())]}
        for cat, v in results.items()
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python sensitive_apis.py <path_to_apk>")
        sys.exit(1)

    loaded = load_apk(sys.argv[1])
    if loaded:
        hits = scan_sensitive_apis(loaded)
        print(json.dumps(hits, indent=2))
