# Android Malware Static Analysis Framework

A completed project for analyzing Android APKs through a single static-analysis pipeline. The framework combines APK ingestion, manifest and signing inspection, DEX feature extraction, category-aware risk scoring, finding correlation, an interactive dashboard, and downloadable HTML security reports.

Analysis reads APK archives and bytecode without installing or executing the application. Results explain the evidence behind each finding and provide review steps for possible attack paths. The implementation is complete for this scope; its heuristic scores and correlations are not a validated malware classifier.

## Contents

- [Features](#features)
- [Architecture and repository structure](#architecture-and-repository-structure)
- [Requirements and installation](#requirements-and-installation)
- [Dashboard](#dashboard)
- [Command-line usage](#command-line-usage)
- [Data and output formats](#data-and-output-formats)
- [Risk scoring and app context](#risk-scoring-and-app-context)
- [Finding correlation](#finding-correlation)
- [Configuration](#configuration)
- [Testing](#testing)
- [Limitations and troubleshooting](#limitations-and-troubleshooting)

## Features

| Area | Implemented capabilities |
| --- | --- |
| APK ingestion | Archive validation, file size, SHA-256 and MD5 hashes, parse status and error reporting |
| Manifest inspection | Package and version metadata, SDK levels, permissions, activities, services, receivers, providers, intent filters and exported-component information |
| Signing inspection | Signing-scheme identification, certificate metadata, debug-certificate and self-signed-certificate indicators |
| DEX analysis | Sensitive API references, API categories, counts and calling methods through Androguard |
| String extraction | URLs, IP addresses and strings used by the analysis and scoring stages |
| Obfuscation and payload inspection | Short-name ratios, high-entropy string indicators, native libraries, known packer indicators and embedded secondary code |
| Structural inspection | Duplicate ZIP entries, archive anomalies and suspicious embedded files |
| Risk assessment | Configurable rule weights, evidence and reasons, bounded permission contributions, risk bands and category-aware adjustments |
| Correlation | Catalog-defined permission, API, endpoint, payload and component associations with evidence levels and verification steps |
| Presentation | Flask dashboard, score and evidence charts, JSON results, self-contained HTML security reports and browser printing to PDF |

Individual indicators can occur in legitimate applications. The framework presents them for review rather than treating each one as proof of malicious behavior.

## Architecture and repository structure

The shared pipeline follows this sequence:

1. Validate and parse the APK with `apk_parser.py`.
2. Extract API, string and obfuscation features with `feature_extraction/`.
3. Build schema v1.0 analysis data and normalize it with `analyzer.py`.
4. Determine app-category context and calculate the explainable risk score.
5. Evaluate `correlation_rules.json` against the normalized features.
6. Display the results in the dashboard or write JSON and HTML artifacts.

Existing analysis JSON can enter at the normalization stage without repeating APK extraction.

```text
MAS/
|-- apk_parser.py
|-- pipeline.py
|-- run.py
|-- requirements.txt
|-- pytest.ini
|-- test_apk_parser.py
|-- feature_extraction/
|-- tests/
|-- samples/
|   |-- org.fdroid.fdroid.apk
|   `-- org.fossify.notes.apk
|-- Framework/android-malware-framework/
|   |-- analyzer.py
|   |-- app.py
|   |-- app_category.py
|   |-- config.py
|   |-- scoring_engine.py
|   |-- correlation_engine.py
|   |-- correlation_rules.json
|   |-- CORRELATION_RULES.md
|   |-- report_generator.py
|   |-- data/
|   |   |-- sample_benign.json
|   |   |-- sample_suspicious.json
|   |   `-- uploads/                  # Created at runtime
|   |-- reports/                      # Generated dashboard reports
|   |-- static/
|   |-- templates/
|   `-- tests/
`-- output/                           # Default CLI output directory
```

Virtual environments, caches, uploaded analysis files and generated output/report artifacts are excluded from Git by `.gitignore`.

## Requirements and installation

- Python 3.10 or newer.
- A browser for the dashboard and HTML reports.
- Python dependencies from the root `requirements.txt`: Androguard 4.x, Flask 3.0.3 and pytest 8.3.2.

Run all commands from the repository root.

### Windows PowerShell

```powershell
cd D:\MAS
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run.py
```

Using the environment's Python directly avoids requiring PowerShell activation.

### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run.py
```

The commands below use `python`; on Windows, substitute `.\.venv\Scripts\python.exe` when the virtual environment is not activated.

## Dashboard

Start the dashboard with:

```bash
python run.py
```

Open **http://127.0.0.1:5000**.

1. Choose a bundled JSON example or upload an `.apk` or analysis `.json`.
2. Review the risk score, risk band, matched rules, app context, permissions, APIs, endpoints and other evidence.
3. Review possible attack paths, their supporting signals, reference mappings and verification steps.
4. Select **Generate Security Report** to view the report, download its HTML copy or print it to PDF through the browser.

Uploads are limited to **100 MB**. APK analysis is synchronous, so larger files can take longer. Uploaded APKs are removed when processing finishes, including when extraction fails. Successful APK analysis is stored as JSON under `Framework/android-malware-framework/data/uploads/`; JSON uploads are retained there. Generated dashboard reports are saved under the framework's `reports/` directory.

Custom address and port:

```bash
python run.py --host 127.0.0.1 --port 5001
```

The bundled server is intended for local project use. It has no authentication or production deployment configuration.

### Web routes

| Route | Purpose |
| --- | --- |
| `GET /` | List available analyses and show the upload form |
| `POST /upload` | Upload an APK or JSON using the multipart field `analysis_file` |
| `GET /analyze?file=<relative-json-path>` | Display an existing analysis |
| `GET /api/analyze?file=<relative-json-path>` | Return its risk result as JSON |
| `GET /report?file=<relative-json-path>` | Generate, save and display a security report |
| `GET /reports/<filename>` | Download a saved HTML report |

The `file` parameter is relative to the framework's `data/` directory, for example `sample_suspicious.json` or `uploads/<saved-name>.json`. It does not accept arbitrary filesystem paths.

## Command-line usage

### Full APK-to-report pipeline

```bash
python pipeline.py samples/org.fossify.notes.apk -o output/fossify-notes
python pipeline.py samples/org.fdroid.fdroid.apk -o output/fdroid
```

### Re-score existing JSON or try a bundled example

```bash
python pipeline.py Framework/android-malware-framework/data/sample_suspicious.json -o output/demo
python pipeline.py Framework/android-malware-framework/data/sample_benign.json -o output/benign-demo
```

Each successful run prints the score and risk band and writes:

| File | Contents |
| --- | --- |
| `analysis.json` | Analysis input used for normalization and scoring; APK runs also preserve original parser and extraction findings |
| `risk.json` | Score, risk band, rule contributions, app context, policy findings, correlations and warnings |
| `report.html` | Self-contained security report for offline viewing or browser printing |

The default output directory is `output/`. Use separate directories for separate scans: rerunning a command in the same directory overwrites these three filenames. Invalid APKs and failed DEX extraction return a nonzero exit code instead of producing an incomplete low-risk assessment.

### Parser-only inspection

```bash
python apk_parser.py samples/org.fossify.notes.apk
python apk_parser.py samples/org.fossify.notes.apk -o output/parser-result.json
```

Create the destination directory first when saving parser output. Parser-only output is ingestion data; use `pipeline.py` for the complete scoring and reporting workflow. The parser exits with `0` on success and `1` for an invalid APK or parse failure.

### Score analysis JSON without generating a report

```bash
python Framework/android-malware-framework/scoring_engine.py Framework/android-malware-framework/data/sample_suspicious.json
```

## Data and output formats

The integrated analysis format has `schema_version: "1.0"`. The bundled [benign example](Framework/android-malware-framework/data/sample_benign.json) and [suspicious example](Framework/android-malware-framework/data/sample_suspicious.json) provide complete sample inputs.

| Analysis section | Contents |
| --- | --- |
| `apk` | Filename, hashes, size, package, label, version and SDK metadata |
| `manifest` | Permissions, components and selected certificate information |
| `code` | Strings, URLs, IPs, sensitive APIs with callers, native libraries and obfuscation indicators |
| `analysis_metadata` | Analysis timestamp, warnings and errors |
| `raw_findings` | Original ingestion, sensitive API and obfuscation results |
| `app_context` | Optional declared category, overriding category inference |

Parser-only JSON includes `file_name`, `file_size_bytes`, `sha256`, `md5`, `status` and `error`. Successful parsing adds `manifest`, `certificates`, `signature_schemes`, `is_signed`, `assets_and_resources` and `structural_anomalies`. Status is `success`, `invalid` or `parse_error`; failed results include an explanation.

Risk results include `risk_score`, `raw_score`, `max_score`, `risk_level`, `risk_level_basis`, `matched_rules`, `policy_violations` and `attack_paths`, together with application/context metadata and warnings. Findings without a dedicated scoring rule remain available in `raw_findings`.

## Risk scoring and app context

The reported score is capped at **100**. Matched rules explain their points, reasons and supporting evidence. Default score bands are:

| Score | Band |
| --- | --- |
| 0-25 | Low |
| 26-50 | Medium |
| 51-75 | High |
| 76-100 | Critical |

Scoring covers sensitive permissions, SMS APIs, command execution, dynamic code loading, suspicious URLs, public IP addresses, obfuscation, certificate indicators, native libraries and unprotected exported components. Permission-volume contributions and category adjustments are bounded.

App context distinguishes expected capabilities from capabilities that are unusual for the application's purpose. The current taxonomy contains **13 categories**:

`kids`, `education`, `navigation`, `messaging`, `social`, `media`, `productivity`, `utilities`, `app_store`, `health`, `finance`, `shopping` and `games`.

Declare a category by adding this top-level field to analysis JSON:

```json
{
  "app_context": {
    "category": "education"
  }
}
```

This fragment is added to an existing analysis object. A declared category takes precedence. Without one, inference uses known package mappings, package/label keywords and permission/API evidence. The inferred category is applied only when its confidence meets the configured threshold; otherwise scoring remains category-neutral and candidate categories are available for review.

Declaring `"category": "unknown"` opts out of inference. `CONTEXT_INFERENCE_ENABLED = False` disables it globally.

Category-specific policy findings are reported separately. The configured policy floor can raise the reported risk band without increasing the numeric score; `risk_level_basis` explains whether the score or that floor determined the band. These are local configured policy checks, not a legal or app-store compliance certification.

A low score means fewer matched indicators under the current rules and context. It does not establish that an application is safe.

## Finding correlation

[correlation_rules.json](Framework/android-malware-framework/correlation_rules.json) is the source of matching conditions and interpretations. The engine loads and validates the catalog before evaluating normalized features. Invalid catalogs raise explicit errors.

Supported associations include:

- Declared SMS access and network capability.
- Declared audio/video capture, background-location and overlay/installation capabilities.
- SMS permission combined with an SMS sending API.
- Contacts, location or device-identifier access combined with Internet permission and a suspicious destination.
- Dynamic loading combined with reflection or shell/process execution.
- Embedded secondary code combined with a dynamic loader.
- An unprotected exported component whose class references a matched sensitive API.

Every result carries its rule ID, catalog version, title, potential impact, confidence, evidence, limitations, verification steps, legitimate-use exceptions, platform constraints, reference mappings and validation metadata.

| Evidence level | Meaning |
| --- | --- |
| `declared_capability` | Related permissions are declared |
| `static_cooccurrence` | Required signals coexist in the APK |
| `shared_caller` | Matched API groups share an exact calling method |
| `same_class_association` | A matched API caller class is an unprotected exported component |

API combinations without shared callers retain low confidence; a shared caller raises their qualitative confidence to moderate. Correlations add **no score points**, avoiding duplicate counting of the underlying findings.

All rules currently remain `unvalidated`, with null detection metrics. Android, OWASP and MITRE references describe platform behavior or related threats; they do not validate the exact matching heuristics. No result proves a runtime attack or a source-to-sink data flow. See the [catalog guide](Framework/android-malware-framework/CORRELATION_RULES.md) for condition definitions, reference interpretation and validation requirements.

## Configuration

[config.py](Framework/android-malware-framework/config.py) contains score bands, rule weights, sensitive permissions, API categorization, URL/IP indicators, category definitions and context settings. Key settings include:

- `MAX_SCORE`, `RISK_LEVELS` and `WEIGHTS`.
- `CONTEXT_TIER_MULTIPLIERS` and `CONTEXT_PERMISSION_ADJUST_CAP`.
- `CONTEXT_POLICY_MIN_LEVEL`.
- `CONTEXT_INFERENCE_ENABLED` and `CONTEXT_INFERENCE_MIN_CONFIDENCE`.
- `APP_CATEGORIES`, `KNOWN_APP_CATEGORIES` and `APP_CATEGORY_KEYWORDS`.

Edit correlation behavior in the JSON catalog, keeping supported condition keys and required metadata intact. Bump `catalog_version` when matching conditions or interpretations change. Change `source_reviewed_on` only after reviewing the references.

## Testing

Run the full suite from the repository root:

```bash
python -m pytest -q
```

The latest verified default run completed with **246 passed and 1 skipped**. The skipped test is the optional real-APK dashboard/report integration test, which requires `MAS_TEST_APK`. A duplicate-ZIP-entry warning is expected from the parser test that deliberately creates one.

Enable the optional integration test with an APK:

```powershell
$env:MAS_TEST_APK = (Resolve-Path .\samples\org.fossify.notes.apk).Path
.\.venv\Scripts\python.exe -m pytest -q
Remove-Item Env:\MAS_TEST_APK
```

```bash
MAS_TEST_APK="$PWD/samples/org.fossify.notes.apk" python -m pytest -q
```

That test covers upload, extraction, JSON persistence, dashboard rendering, saved HTML reporting and APK cleanup. Test coverage also includes invalid archives, parser behavior, feature extraction, scoring, app-category context, catalog validation, correlation matching and escaped report evidence.

The repository includes Fossify Notes and F-Droid APKs for local exercises, plus two synthetic JSON examples. Implementation tests verify program behavior; they do not measure malware-detection precision or recall.

## Limitations and troubleshooting

- Static analysis cannot establish runtime permission grants, user consent, entry-point reachability, actual endpoint use or verified data flow.
- Packed, encrypted, dynamically downloaded or native code can hide behavior from DEX inspection. Packer and certificate-parser issues are reported as warnings where available.
- Manifest exported-component inference includes legacy defaults; modern target-SDK behavior and malformed signing blocks need careful interpretation.
- Category inference is heuristic. Declare a known category when appropriate, and review legitimate-use exceptions before interpreting findings.
- Self-signed certificates, native libraries, reflection and dynamic loading can be normal. The engine filters several common false positives, including launcher exports, loopback destinations, dotted object identifiers and ordinary class-loader references, but broader accuracy has not been established.
- CLI reports are self-contained. Dashboard styling/charts may need network access for externally loaded assets.
- Analysis has no dynamic sandbox, antivirus-signature feed, machine-learning model or integrated source-to-sink analyzer.

| Problem | What to check |
| --- | --- |
| Missing Python module | Install the root requirements using the same virtual-environment Python used to launch the project |
| Port 5000 is occupied | Launch with `python run.py --port 5001` |
| Upload rejected | Use `.apk` or valid analysis `.json` within the 100 MB limit |
| APK analysis fails | Check archive validity and the reported parse/DEX error; no complete assessment is produced for failed extraction |
| JSON accepted but findings are sparse | Compare its structure with the bundled schema v1.0 examples; missing evidence cannot support matching rules |
| Catalog raises `ValueError` | Check IDs, condition keys, nonempty API groups and required unvalidated metadata against the catalog guide |
| Integration test skipped | Set `MAS_TEST_APK` to an existing sample APK |
| Report missing from Git | Runtime reports, uploads and output artifacts are intentionally ignored; generate them locally |

The completed deliverable is the integrated static-analysis workflow, dashboard, reporting system, configurable scoring and catalog-driven correlations. Detection-accuracy validation and runtime analysis are outside the implemented project scope.
