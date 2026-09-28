# Android Malware Static Analysis Framework

The integrated pipeline accepts an APK, parses its manifest and signing data,
extracts DEX features with Androguard, normalizes the results into schema v1.0,
calculates an explainable risk score, and generates an HTML security report.
APK code is never installed or executed.

## Setup and dashboard

Run from the repository root (Python 3.10 or newer):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run.py
```

Open http://127.0.0.1:5000. Upload an `.apk` for the full pipeline, or a
previous analysis `.json`. Uploads are limited to 100 MB. APK analysis runs
synchronously, so large APKs may take some time. The uploaded APK is removed
when processing finishes; the generated JSON remains available in the dashboard.
Use **Generate Security Report** to view, download, or print the report to PDF.

## Command-line pipeline

```bash
python pipeline.py /path/to/app.apk -o output/my-app
python pipeline.py anzal_android-malware-framework/android-malware-framework/data/sample_suspicious.json -o output/demo
```

Each output directory contains:

- `analysis.json`: normalized input for scoring, plus original parser and extraction findings.
- `risk.json`: score, risk band, matched rules, evidence, and warnings.
- `report.html`: self-contained report for offline viewing or printing.

Invalid APKs or failed DEX analysis return a nonzero exit code instead of
producing a misleading low-risk assessment. Failed certificate parsing and
known packers are reported as warnings. Preserve separate output directories
for separate scans; command-line output filenames are overwritten on reruns.

## Module layout

- `apk_parser.py`: archive validation, metadata, manifest, signatures, assets, anomalies.
- `feature_extraction/`: APK loading, API cross-references, strings, obfuscation and payload detection.
- `pipeline.py`: orchestration and conversion to the scoring module's shared JSON schema.
- `run.py`: dashboard launcher.
- `anzal_android-malware-framework/android-malware-framework/`: feature normalization,
  configurable scoring, app-category context, Flask routes, templates, and report generation.
- `anzal_android-malware-framework/android-malware-framework/app_category.py`: the app-category
  taxonomy, category inference, and the tier lookups context-aware scoring uses.

The pipeline preserves findings that do not yet have dedicated scoring rules
(such as archive anomalies and secondary payloads) under `raw_findings`.
The risk score is a manual-review aid; it does not establish whether an APK is malware.

## App-category context

A permission is not risky in isolation: its risk depends on whether the app's
stated purpose justifies it. `ACCESS_FINE_LOCATION` is expected in a navigation
app and out of character in a child-directed one, so scoring both identically is
the main source of false positives in a purely additive model.

Scoring is therefore assessed against an app category, drawn from a fixed
taxonomy of twelve: `kids`, `education`, `navigation`, `messaging`, `social`,
`media`, `productivity`, `utilities`, `health`, `finance`, `shopping` and
`games`. Each category lists which sensitive permissions are expected, which are
out of character, and which are not permitted at all.

Where the category comes from:

- **Declared.** Put an `app_context` block in the analysis JSON. This always wins.
- **Inferred.** With no declaration, the classifier uses a seed table of
  well-known packages (so `com.whatsapp` is recognised as `messaging`), keyword
  evidence from the package name and app label, and the permission/API profile.
  A guess is applied to scoring only when it clears a confidence threshold;
  below that the app is scored category-neutrally and the candidates are still
  reported so a human can decide.

```json
"app_context": { "category": "education" }
```

Declaring `"unknown"` is an explicit opt-out: no inference runs for that file.
Setting `CONTEXT_INFERENCE_ENABLED = False` in `config.py` disables inference
globally, which reproduces the pre-upgrade category-blind numbers exactly
(the demo files return 87 and 4).

What the category changes:

- The sensitive-permission finding keeps its volume cap, which bounds how much
  "how many permissions were requested" can contribute. App context is then
  applied as a bounded adjustment on top (`CONTEXT_PERMISSION_ADJUST_CAP`), so a
  category can still move the finding for an app that already sits at the cap --
  without letting permissions dominate: even fully out of character they stay
  inside the Low band. Set the adjustment to 0 for the cap-only behaviour.
- The SMS, command-execution and dynamic-code-loading rules scale the same way
  for their API family.
- A dedicated rule reports permissions that policy forbids for the category,
  and every finding carries its tier and multiplier in the evidence so the
  arithmetic is auditable.

Compliance is kept on its own axis rather than folded into the score. The score
remains the sum of the findings -- which is what the report explains -- but a
policy violation is reported in its own `policy_violations` field and raises the
reported risk band (`risk_level_basis` records whether the band came from the
score or from the policy floor). A child-directed app requesting location or
contacts therefore cannot be presented as a low-risk result, and the report says
explicitly why the band was raised.

`denied` permissions are deliberately limited to child-directed apps, where
Google Play's Families policy and COPPA provide a citable basis. They are
excluded from the permission finding so the same evidence is never counted
twice.

The dashboard and the generated report both show the category, how it was
determined, the confidence, and the evidence behind it. Because risk is now
relative to context, a low score means "unremarkable *for this kind of app*",
not "safe".

## Calibration against real applications

The scoring path was validated by running real, known-benign applications
through it (a FOSS notes app and the F-Droid client). That surfaced four
false-positive sources, each of which is now fixed and covered by tests:

| Symptom | Cause | Fix |
| --- | --- | --- |
| "Dynamic code loading" (+12) on almost every app | `ClassLoader; loadClass` listed as suspicious in `feature_extraction/sensitive_apis.py`, although the base class loader is the standard class-resolution path | Pattern removed; the file-backed `DexClassLoader` / `PathClassLoader` / `InMemoryDexClassLoader` patterns remain |
| 141 "hardcoded IP addresses" in one app | `IP_RE` matched the first four numbers of a longer dotted run, so X.509/ASN.1 object identifiers were extracted as IPs (`1.3.6.1.4.1.44` produced `1.3.6.1`) | Lookarounds require a complete, delimited dotted-decimal run |
| "Code obfuscation" (+9) on a non-obfuscated FOSS app | `string_encryption_suspected` was true whenever *any* high-entropy string existed | Requires both a count floor and a share of the string pool (`obfuscation_heuristics.MIN_ENTROPY_RATIO`) |
| An app store scored as if installing apps were suspicious | No category described package managers | `app_store` category added, where installing and querying packages is expected |

Also corrected: URL-shortener matching was substring-based, so `www.reddit.com`
was reported as a shortened link (it contains `t.co`), and loopback URLs such as
`http://127.0.0.1` were flagged even though `PRIVATE_IP_PREFIXES` already
declared loopback benign for the IP rule. Exported launcher activities are now
excluded from the exported-component finding, because Android requires an
app's entry point to be exported.

Measured effect on the two benign applications:

| Application | Before | After |
| --- | --- | --- |
| Fossify Notes (FOSS notes app, inferred `productivity`) | 45 / Medium | **24 / Low** |
| F-Droid client (inferred `app_store`) | 75 / High | **45 / Medium** |

The remaining contributors on the F-Droid client are defensible rather than
mistaken: a self-signed certificate (every F-Droid app has one), bundled native
libraries, exported components, command execution (it drives the platform
package manager), and a handful of plain-HTTP library documentation URLs. The
entropy thresholds are a reasoned starting point, not a calibrated result --
they should be revisited against a labelled corpus.

## Tests

```bash
python -m pytest -q
MAS_TEST_APK=/path/to/test.apk python -m pytest -q
```

The optional real-APK test exercises upload, analysis, dashboard rendering,
and saved report generation. Use a trusted test APK. The original ingestion
module notes follow below.

---

# Person A — Ingestion & Parsing Module

## What this module does

Takes a raw `.apk` file and produces a single structured JSON object containing:

1. File-level metadata and integrity hashes
2. Full AndroidManifest.xml parsing (permissions, components, intent filters)
3. Certificate/signing analysis, including debug-certificate detection
4. Resource/asset inspection for embedded payloads
5. Structural anomaly checks (zip bombs, duplicate entries)

This JSON is the **input contract** for Person B (feature extraction) and,
downstream, Person C (scoring engine). Any change to this schema must be
communicated to both before merging.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python apk_parser.py sample.apk
python apk_parser.py sample.apk -o result.json
```

Exit code is `0` on success, `1` if the APK was invalid or failed to parse
(status will explain why — see schema below).

## Output schema

```jsonc
{
  "file_name": "sample.apk",
  "file_size_bytes": 4213556,
  "sha256": "…",
  "md5": "…",
  "status": "success",          // "success" | "invalid" | "parse_error"
  "error": null,                // populated when status != "success"
  "is_signed": true,

  "manifest": {
    "package_name": "com.example.app",
    "app_name": "Example",
    "version_name": "1.2.0",
    "version_code": 12,
    "min_sdk": 21,
    "target_sdk": 34,
    "max_sdk": null,
    "permissions": ["android.permission.SEND_SMS", "..."],
    "declared_permissions": ["..."],
    "custom_permissions": ["..."],

    "activities": [
      {
        "name": "com.example.app.MainActivity",
        "exported": true,
        "has_permission": false,
        "intent_filters": { "action": ["android.intent.action.MAIN"], "category": ["..."] }
      }
    ],
    "services": [ /* same shape as activities */ ],
    "receivers": [ /* same shape as activities */ ],
    "providers": ["..."],

    "main_activity": "com.example.app.MainActivity",
    "is_multidex": false,
    "libraries": ["..."],
    "uses_features": ["android.hardware.camera", "..."],

    "unprotected_exported_components": [
      { "type": "receiver", "name": "com.example.app.SmsReceiver" }
    ],
    "has_persistence_receiver": true,
    "persistence_receivers": ["com.example.app.BootReceiver"]
  },

  "certificates": [
    {
      "subject": "CN=Example Corp",
      "issuer": "CN=Example Corp",
      "serial_number": "123456789",
      "not_before": "2020-01-01 00:00:00",
      "not_after": "2050-01-01 00:00:00",
      "sha256_fingerprint": "AB:CD:...",
      "is_self_signed": true,
      "is_debug_certificate": false
    }
  ],
  "signature_schemes": { "v1_signed": true, "v2_signed": true, "v3_signed": false },

  "assets_and_resources": {
    "suspicious_embedded_files": [
      { "path": "assets/payload.dex", "size_bytes": 20480, "compressed_size_bytes": 8192 }
    ],
    "native_libraries": ["lib/arm64-v8a/libnative.so"],
    "architectures": ["arm64-v8a", "armeabi-v7a"],
    "asset_file_count": 12,
    "res_file_count": 340
  },

  "structural_anomalies": [
    { "type": "duplicate_zip_entries", "detail": ["res/layout/main.xml"], "severity": "high" }
  ]
}
```

## Security findings this module surfaces (for Person C's scoring rules)

| Field | Why it matters |
|---|---|
| `unprotected_exported_components` | Exported activity/service/receiver with no permission guard — any app on the device can invoke it |
| `has_persistence_receiver` | `BOOT_COMPLETED`/`QUICKBOOT_POWERON` receivers indicate the app tries to auto-start, a common malware persistence technique |
| `certificates[].is_debug_certificate` | Debug-signed "release" apps are a red flag — shouldn't happen in production |
| `certificates[].is_self_signed` | Common in malware since there's no CA vetting, though many legitimate small apps also self-sign |
| `signature_schemes` | Apps only using old, weaker V1 signing may be easier to tamper with |
| `assets_and_resources.suspicious_embedded_files` | Secondary `.dex`/`.apk`/`.so` files bundled outside expected locations — classic payload-dropping technique |
| `structural_anomalies` | Zip bombs / duplicate entries — parser-confusion and DoS techniques, also used to evade some scanners |

## Testing

See `test_apk_parser.py`. Run with:

```bash
pytest test_apk_parser.py -v
```

Get test samples:
- **Benign**: any APK from [F-Droid](https://f-droid.org) (open source, safe)
- **Malicious**: only from a proper research corpus (e.g. CICMalDroid2020,
  Drebin), inside an isolated VM with networking disabled. Never run/install
  these files — this module only reads the archive statically.

## Known limitations / things to revisit

- `_is_exported` uses the pre-API-31 default-exported behavior for components
  with intent filters; from Android 12+ apps must declare `exported`
  explicitly, so this heuristic may need adjusting once we test against newer
  target-SDK samples.
- Certificate parsing assumes standard v1-v3 JAR/APK signing; edge cases in
  malformed or adversarially crafted signature blocks may raise exceptions
  (caught and reported, but worth expanding test coverage on).
