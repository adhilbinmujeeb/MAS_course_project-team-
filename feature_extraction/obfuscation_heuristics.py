"""
obfuscation_heuristics.py
-------------------------

Person B - Android Malware Static Analysis Framework

Detects:

1. ProGuard/R8-style short class and method names (scoped to the app's
   own package, with a ratio-based score in addition to raw counts)
2. High-entropy / random-looking DEX strings
3. Native shared libraries (.so) inside the APK, including fingerprinting
   of known commercial packers/protectors (Jiagu, SecShell, Ijiami, etc.)
4. Secondary/embedded payloads (DEX, JAR, or APK files bundled inside
   assets/ or elsewhere) that indicate multi-stage / dynamic loading,
   a common static-analysis evasion technique

The APK package name is obtained automatically from Androguard.

IMPORTANT:
These are static-analysis heuristics. They do not prove that an APK
is malicious or that an application is obfuscated. Treat all findings
as signals to be combined/weighted by the scoring engine (Person C),
not standalone verdicts.

CHANGELOG vs. original draft:
- Added commercial packer/protector fingerprinting (native lib names).
- Added secondary-payload detection (embedded dex/jar/apk).
- Added ratio-based obfuscation scores (short_class_ratio, etc.) in
  addition to raw counts, so results are comparable across app sizes.
- Precompiled all regexes at module load instead of per-call.
- Removed duplicate entropy computation (was calculated twice per
  candidate string).
- Added explicit "package_detection_failed" fallback: if Androguard
  can't resolve the package name, we no longer silently return empty
  results — we fall back to "all non-external classes" and flag it.
- Added per-ABI breakdown for native libraries.
"""

from __future__ import annotations

import json
import math
import re
import sys
import zipfile
from typing import Dict, List, Optional

try:
    from .apk_loader import LoadedAPK, load_apk
except ImportError:
    from apk_loader import LoadedAPK, load_apk


# ============================================================================
# Configuration
# ============================================================================

# ProGuard/R8 commonly generates names such as:
#
#     a
#     b
#     aa
#     ab
#
SHORT_NAME_RE = re.compile(r"^[a-z]{1,2}$")

# Strings shorter than this are ignored by the entropy detector.
MIN_ENTROPY_STRING_LENGTH = 20

# Shannon entropy threshold.
HIGH_ENTROPY_THRESHOLD = 4.5

# A random-looking string should normally contain at least this many
# numerical characters.
MIN_DIGIT_COUNT = 2

# High-entropy strings are only reported as *suspected string encryption* when
# they are both numerous and a meaningful share of the string pool.
#
# Presence alone is worthless as a signal: embedded resources, fonts, icons,
# certificates and base64 in third-party libraries all produce them. Measured
# examples -- a FOSS notes app produced 4 of 22,586 strings (0.02%) and the
# F-Droid client 1,184 of 122,586 (0.97%) -- so a "count > 0" test, which is
# what this used to be downstream, flagged both as encrypted.
#
# NOTE: these two numbers are a reasoned starting point, not a calibrated
# result. They should be revisited against a labelled corpus; a genuinely
# string-encrypted payload typically hides a large share of its own strings.
MIN_ENTROPY_FINDINGS = 25
MIN_ENTROPY_RATIO = 0.02


# ---------------------------------------------------------------------------
# Known framework/library namespaces
# ---------------------------------------------------------------------------

LIBRARY_PREFIXES = (
    "Landroid/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Landroidx/",
    "Lcom/google/",
    "Lcom/android/",
    "Lcom/squareup/",
    "Lcom/facebook/",
    "Lcom/fasterxml/",
    "Lorg/apache/",
    "Lorg/json/",
    "Lorg/xml/",
    "Lorg/w3c/",
    "Lorg/xmlpull/",
    "Lsun/",
)

COMMON_STRING_PREFIXES = (
    "android.",
    "androidx.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "com.android.",
    "org.apache.",
    "org.xml.",
    "org.w3c.",
)

COMMON_STRING_SUBSTRINGS = (
    "http://schemas.android.com",
    "https://schemas.android.com",
    "www.w3.org",
    "xmlpull.org",
)


# ---------------------------------------------------------------------------
# Known commercial packer / protector fingerprints
# ---------------------------------------------------------------------------
#
# Malware authors frequently wrap payloads with commercial "app
# protection" packers specifically because they defeat naive static
# analysis (classes.dex is a tiny stub; the real code is decrypted and
# loaded at runtime from a native library). Presence of one of these
# is a strong signal that static analysis of classes.dex alone will
# be incomplete, and is itself worth flagging/scoring.
#
# Mapping: packer/vendor label -> substrings matched against native
# library filenames (case-insensitive, without the "lib" prefix or
# ".so" suffix requirement).
PACKER_SO_FINGERPRINTS = {
    "Qihoo 360 Jiagu": ("jiagu",),
    "Bangcle / SecShell": ("secexe", "secmain", "secnative"),
    "Ijiami": ("execmain", "mixed.dat", "ijmutil", "ijiami"),
    "Tencent Legu": ("shell-super", "shella", "shellx", "tup"),
    "Baidu Protect": ("baiduprotect",),
    "NQ Shield": ("nqshield",),
    "Alibaba / Mobisec": ("mobisec", "msaoaidsec"),
    "APKProtect": ("apkprotect",),
    "Naga / Nagapt": ("naga",),
    "Kiro / Kiro-P": ("kirop",),
}

# Filenames (relative to the APK root) that indicate a secondary
# payload bundled for dynamic/runtime loading — a common technique to
# hide code from static scanners that only look at classes*.dex.
SECONDARY_PAYLOAD_EXTENSIONS = (".dex", ".jar", ".apk")


# ============================================================================
# Precompiled regex patterns (compiled once at import time, not per call)
# ============================================================================

_TYPE_DESCRIPTOR_RE = re.compile(
    r"^\[?L[A-Za-z0-9_$]+(/[A-Za-z0-9_$]+)+;?$"
)

_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)

_JAVA_PACKAGE_RE = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+"
)

_SLASH_PATH_RE = re.compile(r"[A-Za-z0-9_$./:-]+")

_ALPHA_ONLY_RE = re.compile(r"[^A-Za-z]")

_REGEX_MARKERS = (
    "(?:", "(?=", "(?!", "\\b", "\\d", "\\w", "\\s",
    "{0,", "{1,", ".*", ".+", "[]",
)


# ============================================================================
# Package name
# ============================================================================

def get_application_package(loaded: LoadedAPK) -> str:
    """
    Obtain the application's package name directly from the APK.

    Androguard's APK object exposes get_package().
    """
    try:
        package_name = loaded.apk.get_package()
        if package_name:
            return package_name
    except Exception:
        pass

    return ""


# ============================================================================
# Entropy calculation
# ============================================================================

def calculate_entropy(value: str) -> float:
    """
    Calculate Shannon entropy. Higher entropy means the characters are
    distributed more randomly.
    """
    if not value:
        return 0.0

    frequencies: Dict[str, int] = {}
    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1

    length = len(value)
    entropy = 0.0
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


# ============================================================================
# Class/package helpers
# ============================================================================

def normalize_class_name(class_name: str) -> str:
    """
    Convert a DEX class name (Lcom/example/MyClass;) into a normal
    Java-style class name (com.example.MyClass).
    """
    value = class_name
    if value.startswith("L"):
        value = value[1:]
    if value.endswith(";"):
        value = value[:-1]
    return value.replace("/", ".")


def belongs_to_application(class_name: str, package_name: str) -> bool:
    """
    Determine whether a class belongs to the application's package.

    Example:
        package: com.example.app
        accepted: com.example.app.MainActivity, com.example.app.utils.Helper
        rejected: androidx.appcompat.AppCompatActivity, com.google.gson.Gson
    """
    if not package_name:
        return False

    normalized = normalize_class_name(class_name)
    return normalized == package_name or normalized.startswith(package_name + ".")


# ============================================================================
# ProGuard/R8 filtering
# ============================================================================

def detect_short_names(
    loaded: LoadedAPK,
    package_name: str,
) -> Dict[str, object]:
    """
    Detect short class/method names, scoped to the application's own
    package whenever the package name is known.

    Falls back to "all non-external classes" (with a flag set) if the
    package name could not be resolved, so a failed package lookup
    doesn't silently produce an empty, misleading report.
    """
    short_classes = set()
    short_methods = set()
    total_app_classes = 0
    total_app_methods = 0

    package_known = bool(package_name)

    for cls in loaded.analysis.get_classes():

        if cls.is_external():
            continue

        class_name = cls.name

        if package_known:
            if not belongs_to_application(class_name, package_name):
                continue
        # else: package unknown -> best-effort, treat every
        # non-external class as in-scope.

        total_app_classes += 1
        normalized_class = normalize_class_name(class_name)
        simple_class_name = normalized_class.split(".")[-1]

        if SHORT_NAME_RE.fullmatch(simple_class_name):
            short_classes.add(normalized_class)

        for method in cls.get_methods():
            total_app_methods += 1
            method_name = method.name
            if SHORT_NAME_RE.fullmatch(method_name):
                short_methods.add(f"{normalized_class};; {method_name}")

    short_class_count = len(short_classes)
    short_method_count = len(short_methods)

    return {
        "package_detection_failed": not package_known,
        "short_class_names": sorted(short_classes),
        "short_method_names": sorted(short_methods),
        "short_class_name_count": short_class_count,
        "short_method_name_count": short_method_count,
        "total_application_classes": total_app_classes,
        "total_application_methods": total_app_methods,
        # Ratios matter more than raw counts once app size varies —
        # a 5,000-class app with 40 short names looks very different
        # from a 60-class app with 40 short names.
        "short_class_ratio": round(
            short_class_count / total_app_classes, 4
        ) if total_app_classes else 0.0,
        "short_method_ratio": round(
            short_method_count / total_app_methods, 4
        ) if total_app_methods else 0.0,
    }


# ============================================================================
# String filters
# ============================================================================

def is_type_descriptor(value: str) -> bool:
    """Ignore Java/DEX type descriptors, e.g. Landroid/graphics/Bitmap;"""
    return _TYPE_DESCRIPTOR_RE.fullmatch(value) is not None


def is_generic_signature(value: str) -> bool:
    """Ignore Java generic/type signatures."""
    if "<" in value and ">" in value:
        if value.startswith("L") or value.startswith("[L"):
            return True
    return False


def is_regex_like(value: str) -> bool:
    """
    Detect regular-expression-like strings. Long regex definitions are
    common in legitimate libraries and can have high Shannon entropy.
    """
    marker_count = sum(marker in value for marker in _REGEX_MARKERS)
    return marker_count >= 2


def is_normal_library_string(value: str) -> bool:
    """Filter common Android/framework/library strings."""
    lower = value.lower()

    for prefix in COMMON_STRING_PREFIXES:
        if lower.startswith(prefix.lower()):
            return True

    for substring in COMMON_STRING_SUBSTRINGS:
        if substring.lower() in lower:
            return True

    return False


def is_url(value: str) -> bool:
    return _URL_RE.match(value) is not None


def is_email(value: str) -> bool:
    return _EMAIL_RE.fullmatch(value) is not None


def is_package_or_path(value: str) -> bool:
    """Ignore ordinary Java package names, paths and class-like strings."""
    if _JAVA_PACKAGE_RE.fullmatch(value):
        return True

    if "/" in value and _SLASH_PATH_RE.fullmatch(value):
        return True

    return False


def punctuation_ratio(value: str) -> float:
    """Calculate proportion of punctuation characters."""
    if not value:
        return 1.0

    punctuation = sum(
        not char.isalnum() and not char.isspace() for char in value
    )
    return punctuation / len(value)


def looks_like_normal_sentence(value: str) -> bool:
    """
    Filter ordinary English/library messages. Long human-readable
    messages are not useful obfuscation indicators.
    """
    words = value.split()
    if len(words) < 5:
        return False

    alphabetic_words = 0
    for word in words:
        clean = _ALPHA_ONLY_RE.sub("", word)
        if len(clean) >= 3:
            alphabetic_words += 1

    return alphabetic_words >= 5


def looks_random(value: str) -> bool:
    """
    Determine whether a string has characteristics of encoded/random
    data: at least two digits AND mixed case, or several digits alone.
    """
    digit_count = sum(char.isdigit() for char in value)
    uppercase_count = sum(char.isupper() for char in value)
    lowercase_count = sum(char.islower() for char in value)

    if digit_count >= MIN_DIGIT_COUNT and uppercase_count >= 2 and lowercase_count >= 2:
        return True

    if digit_count >= 4:
        return True

    return False


# ============================================================================
# High entropy candidate
# ============================================================================

def is_high_entropy_candidate(value: str, entropy: Optional[float] = None) -> bool:
    """
    Apply all false-positive filters before reporting a string.

    `entropy` may be passed in if it has already been computed by the
    caller, to avoid calculating Shannon entropy twice per string.
    """
    if not value:
        return False

    if len(value) < MIN_ENTROPY_STRING_LENGTH:
        return False

    if is_normal_library_string(value):
        return False

    if is_type_descriptor(value):
        return False

    if is_generic_signature(value):
        return False

    if is_url(value):
        return False

    if is_email(value):
        return False

    if is_package_or_path(value):
        return False

    if is_regex_like(value):
        return False

    if looks_like_normal_sentence(value):
        return False

    if entropy is None:
        entropy = calculate_entropy(value)

    if entropy < HIGH_ENTROPY_THRESHOLD:
        return False

    if not looks_random(value):
        return False

    return True


# ============================================================================
# High entropy detection
# ============================================================================

def detect_high_entropy_strings(loaded: LoadedAPK) -> List[Dict[str, object]]:
    """Detect high-entropy strings that also look like encoded/random data."""
    findings = set()

    for dex in loaded.dex_files:
        for value in dex.get_strings():

            # Cheap filters first, entropy (relatively expensive) last —
            # and computed only once.
            if not value or len(value) < MIN_ENTROPY_STRING_LENGTH:
                continue
            if is_normal_library_string(value):
                continue
            if is_type_descriptor(value):
                continue
            if is_generic_signature(value):
                continue
            if is_url(value):
                continue
            if is_email(value):
                continue
            if is_package_or_path(value):
                continue
            if is_regex_like(value):
                continue
            if looks_like_normal_sentence(value):
                continue

            entropy = calculate_entropy(value)
            if entropy < HIGH_ENTROPY_THRESHOLD:
                continue
            if not looks_random(value):
                continue

            findings.add((value, round(entropy, 3)))

    results = []
    for value, entropy in sorted(findings, key=lambda item: (-item[1], item[0])):
        results.append({
            "string": value,
            "length": len(value),
            "entropy": entropy,
        })

    return results


def count_dex_strings(loaded: LoadedAPK) -> int:
    """Total DEX string constants, the denominator for entropy ratios."""
    return sum(len(dex.get_strings()) for dex in loaded.dex_files)


def suspected_string_encryption(high_entropy_count: int, strings_examined: int) -> bool:
    """
    Decide whether high-entropy strings are numerous enough to suggest that
    the application encrypts its own strings.

    Requires both an absolute floor and a share of the string pool, so that
    neither a large application full of legitimate encoded resources nor a
    tiny application with a handful of blobs is flagged.
    """
    if not strings_examined:
        return False
    if high_entropy_count < MIN_ENTROPY_FINDINGS:
        return False
    return (high_entropy_count / strings_examined) >= MIN_ENTROPY_RATIO


# ============================================================================
# Native library detection + packer fingerprinting
# ============================================================================

def _identify_packer(so_filename: str) -> Optional[str]:
    """Return the packer/vendor label if a .so filename matches a
    known commercial packer/protector fingerprint, else None."""
    lower = so_filename.lower()
    for vendor, markers in PACKER_SO_FINGERPRINTS.items():
        if any(marker in lower for marker in markers):
            return vendor
    return None


def detect_native_libraries(loaded: LoadedAPK) -> Dict[str, object]:
    """
    Check the APK ZIP archive for native .so libraries, break them
    down per ABI, and fingerprint known commercial packers/protectors.

    Packer presence matters more than plain "has native code": most
    legitimate apps ship native libraries too (crash reporters, media
    codecs, etc.), but a *known packer* specifically means classes.dex
    is likely a decryption stub and static analysis of it alone is
    incomplete.
    """
    libraries = set()
    abis = {}
    detected_packers = set()

    try:
        with zipfile.ZipFile(loaded.path, "r") as apk_zip:
            for filename in apk_zip.namelist():
                normalized = filename.replace("\\", "/")

                if normalized.startswith("lib/") and normalized.endswith(".so"):
                    libraries.add(normalized)

                    parts = normalized.split("/")
                    if len(parts) >= 3:
                        abi = parts[1]
                        so_name = parts[-1]
                        abis.setdefault(abi, []).append(so_name)

                        packer = _identify_packer(so_name)
                        if packer:
                            detected_packers.add(packer)

    except (zipfile.BadZipFile, OSError) as exc:
        return {
            "present": False,
            "count": 0,
            "libraries": [],
            "abis": {},
            "known_packers_detected": [],
            "error": str(exc),
        }

    return {
        "present": bool(libraries),
        "count": len(libraries),
        "libraries": sorted(libraries),
        "abis": {abi: sorted(set(names)) for abi, names in abis.items()},
        "known_packers_detected": sorted(detected_packers),
    }


# ============================================================================
# Secondary / embedded payload detection
# ============================================================================

def detect_secondary_payloads(loaded: LoadedAPK) -> Dict[str, object]:
    """
    Look for extra DEX/JAR/APK files bundled inside the APK beyond the
    expected top-level classes*.dex. Loading a hidden secondary payload
    at runtime (commonly from assets/) is a widely used technique to
    hide the real malicious code from static scanners, since tools that
    only parse the top-level DEX files never see it.
    """
    suspicious_files = []

    try:
        with zipfile.ZipFile(loaded.path, "r") as apk_zip:
            for filename in apk_zip.namelist():
                normalized = filename.replace("\\", "/")
                lower = normalized.lower()

                # Top-level classesN.dex is normal and expected; ignore it.
                if re.fullmatch(r"classes\d*\.dex", normalized):
                    continue

                if lower.endswith(SECONDARY_PAYLOAD_EXTENSIONS):
                    suspicious_files.append(normalized)

    except (zipfile.BadZipFile, OSError) as exc:
        return {
            "present": False,
            "count": 0,
            "files": [],
            "error": str(exc),
        }

    return {
        "present": bool(suspicious_files),
        "count": len(suspicious_files),
        "files": sorted(suspicious_files),
    }


# ============================================================================
# Main analysis
# ============================================================================

def analyze_obfuscation(loaded: LoadedAPK) -> Dict[str, object]:
    """Execute all obfuscation/evasion heuristics and return a single
    structured findings dict (the feature-vector contract for Person C)."""

    package_name = get_application_package(loaded)

    short_names = detect_short_names(loaded, package_name)
    high_entropy = detect_high_entropy_strings(loaded)
    native_libraries = detect_native_libraries(loaded)
    secondary_payloads = detect_secondary_payloads(loaded)
    strings_examined = count_dex_strings(loaded)

    high_entropy_summary = {
        "threshold": HIGH_ENTROPY_THRESHOLD,
        "minimum_length": MIN_ENTROPY_STRING_LENGTH,
        "count": len(high_entropy),
        "strings_examined": strings_examined,
        "ratio": (round(len(high_entropy) / strings_examined, 5)
                  if strings_examined else 0.0),
        "minimum_findings": MIN_ENTROPY_FINDINGS,
        "minimum_ratio": MIN_ENTROPY_RATIO,
        "findings": high_entropy,
    }
    high_entropy_summary["suspected_string_encryption"] = suspected_string_encryption(
        high_entropy_summary["count"], strings_examined
    )

    return {
        "application_package": package_name,

        "proguard_obfuscation": short_names,

        "high_entropy_strings": high_entropy_summary,

        "native_libraries": native_libraries,

        "secondary_payloads": secondary_payloads,
    }


# ============================================================================
# Command-line interface
# ============================================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python obfuscation_heuristics.py <path_to_apk>")
        sys.exit(1)

    apk_path = sys.argv[1]

    loaded = load_apk(apk_path)
    if loaded is None:
        sys.exit(1)

    findings = analyze_obfuscation(loaded)

    print(json.dumps(findings, indent=2, ensure_ascii=False))
