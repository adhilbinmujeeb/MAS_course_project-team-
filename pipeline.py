"""APK-to-report pipeline shared by the command line and Flask dashboard."""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

FRAMEWORK_DIR = Path(__file__).resolve().parent / 'anzal_android-malware-framework' / 'android-malware-framework'
sys.path.insert(0, str(FRAMEWORK_DIR))


class AnalysisError(ValueError):
    """An APK could not be fully analyzed."""


def analyze_apk(path):
    from apk_parser import parse_apk
    from feature_extraction.apk_loader import load_apk
    from feature_extraction.sensitive_apis import scan_sensitive_apis
    from feature_extraction.string_extraction import extract_strings
    from feature_extraction.obfuscation_heuristics import analyze_obfuscation

    parsed = parse_apk(path)
    if parsed['status'] != 'success':
        raise AnalysisError(parsed['error'])
    loaded = load_apk(str(path))
    if loaded is None:
        raise AnalysisError('DEX analysis failed; no complete risk assessment was produced.')
    api_hits = scan_sensitive_apis(loaded)
    strings = extract_strings(loaded)
    obf = analyze_obfuscation(loaded)
    manifest = parsed['manifest']
    categories = {'sms_fraud': 'sms', 'shell_and_process_exec': 'command_execution',
                  'device_fingerprinting': 'device_info', 'crypto_usage': 'encoding'}
    apis = [{'api': match['api'], 'category': categories.get(category, category),
             'count': match['count'], 'class': ', '.join(match['callers']),
             'callers': match['callers']} for category, hit in api_hits.items()
            for match in hit['matches']]
    short = obf['proguard_obfuscation']
    ratio = max(short['short_class_ratio'], short['short_method_ratio'])
    indicators = []
    if ratio >= .5:
        indicators.append(f'Short class names: {short["short_class_ratio"]:.0%}; short method names: {short["short_method_ratio"]:.0%}')
    if obf['high_entropy_strings']['count']:
        indicators.append(f'{obf["high_entropy_strings"]["count"]} high-entropy strings')
    for packer in obf['native_libraries']['known_packers_detected']:
        indicators.append(f'Known packer: {packer}')
    if obf['secondary_payloads']['present']:
        indicators.append('Embedded code payloads: ' + ', '.join(obf['secondary_payloads']['files']))
    certs = parsed['certificates']
    certificate = next((c for c in certs if c.get('is_debug_certificate')), next((c for c in certs if 'error' not in c), {}))
    certificate = dict(certificate)
    certificate['valid_from'] = certificate.get('not_before')
    certificate['valid_to'] = certificate.get('not_after')
    warnings = [c['error'] for c in certs if 'error' in c]
    if short['package_detection_failed']:
        warnings.append('Package detection failed; obfuscation analysis used all internal classes.')
    if obf['native_libraries']['known_packers_detected']:
        warnings.append('Packed code may conceal functionality from static DEX analysis.')
    native = {}
    for abi, names in obf['native_libraries']['abis'].items():
        for name in names:
            native.setdefault(name, []).append(abi)
    components = {kind: manifest[kind] for kind in ['activities', 'services', 'receivers']}
    components['providers'] = [dict(name=name,
        exported=str(loaded.apk.get_attribute_value('provider', 'exported', name=name) or '').lower() == 'true',
        permission=loaded.apk.get_attribute_value('provider', 'permission', name=name)) for name in manifest['providers']]
    return {
        'schema_version': '1.0',
        'apk': {**{k: parsed[k] for k in ['file_name', 'file_size_bytes', 'sha256', 'md5']},
                **{k: manifest[k] for k in ['package_name', 'version_name', 'version_code', 'min_sdk', 'target_sdk']},
                'app_label': manifest['app_name']},
        'manifest': {**manifest, 'components': components, 'certificate': certificate},
        'code': {**strings, 'suspicious_apis': apis,
                 'native_libraries': [{'name': name, 'architectures': abis} for name, abis in sorted(native.items())],
                 'obfuscation': {'is_obfuscated': ratio >= .5 or bool(obf['native_libraries']['known_packers_detected']),
                     'short_name_ratio': ratio, 'reflection_used': 'reflection' in api_hits,
                     'string_encryption_suspected': bool(obf['high_entropy_strings']['count']), 'indicators': indicators}},
        'analysis_metadata': {'analyzed_at': datetime.now(timezone.utc).isoformat(), 'warnings': warnings, 'errors': []},
        'raw_findings': {'ingestion': parsed, 'sensitive_apis': api_hits, 'obfuscation': obf},
    }


def run_pipeline(path):
    from analyzer import build_features
    from scoring_engine import calculate_risk
    path = Path(path)
    raw = analyze_apk(path) if path.suffix.lower() == '.apk' else json.loads(path.read_text(encoding='utf-8'))
    features = build_features(raw)
    return raw, features, calculate_risk(features)


def main():
    parser = argparse.ArgumentParser(description='Analyze an APK or existing analysis JSON and generate a security report.')
    parser.add_argument('input', type=Path)
    parser.add_argument('-o', '--output-dir', type=Path, default=Path('output'))
    args = parser.parse_args()
    try:
        raw, features, result = run_pipeline(args.input)
        from app import app
        import report_generator
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / 'analysis.json').write_text(json.dumps(raw, indent=2, default=str), encoding='utf-8')
        (args.output_dir / 'risk.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        with app.app_context():
            context = report_generator.build_report_context(features, result, args.input.name)
            html = report_generator.render_report_html(context)
        (args.output_dir / 'report.html').write_text(html, encoding='utf-8')
    except (AnalysisError, OSError, ValueError) as exc:
        parser.exit(1, f'Analysis failed: {exc}\n')
    print(f'{result["apk_name"]}: {result["risk_score"]}/100 ({result["risk_level"]})')
    print(f'Results saved to {args.output_dir.resolve()}')


if __name__ == '__main__':
    main()
