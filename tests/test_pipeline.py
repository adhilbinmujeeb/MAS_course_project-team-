import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from pipeline import AnalysisError, FRAMEWORK_DIR, analyze_apk, run_pipeline
from feature_extraction.sensitive_apis import scan_sensitive_apis


def test_sensitive_api_matches_dex_descriptor():
    call = SimpleNamespace(class_name='Landroid/telephony/SmsManager;', name='sendTextMessage')
    method = SimpleNamespace(name='send', get_xref_to=lambda: [(None, call, 0)])
    cls = SimpleNamespace(name='Lcom/example/Sender;', is_external=lambda: False, get_methods=lambda: [method])
    loaded = SimpleNamespace(analysis=SimpleNamespace(get_classes=lambda: [cls]))
    hits = scan_sensitive_apis(loaded)
    assert hits['sms_fraud']['matches'][0]['api'] == 'Landroid/telephony/SmsManager; sendTextMessage'
    assert hits['sms_fraud']['count'] == 1


def test_json_pipeline_preserves_sample_score():
    raw, features, result = run_pipeline(FRAMEWORK_DIR / 'data/sample_suspicious.json')
    # 87 before the app-context upgrade. The sample's label ("Battery Saver
    # Pro") is now inferred as the 'utilities' category, which makes its SMS
    # usage and most of its permissions out of character. See
    # tests/test_app_category.py for the category-neutral baseline of 87.
    assert result['risk_score'] == 100
    assert features['package_name'] == raw['apk']['package_name']


def test_invalid_apk_never_produces_low_risk_result(tmp_path):
    path = tmp_path / 'broken.apk'
    path.write_bytes(b'not an APK')
    with pytest.raises(AnalysisError):
        analyze_apk(path)


def test_failed_apk_upload_is_removed(tmp_path, monkeypatch):
    import app as web
    monkeypatch.setattr(web, 'UPLOAD_DIR', tmp_path)
    web.app.config['TESTING'] = True
    with web.app.test_client() as client:
        response = client.post('/upload', data={'analysis_file': (io.BytesIO(b'broken'), 'bad.apk')}, follow_redirects=True)
    assert response.status_code == 200
    assert b'APK analysis failed' in response.data
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(not os.environ.get('MAS_TEST_APK'), reason='Set MAS_TEST_APK to a real test APK')
def test_real_apk_to_dashboard_and_report(tmp_path, monkeypatch):
    import app as web
    import report_generator
    monkeypatch.setattr(web, 'UPLOAD_DIR', tmp_path)
    monkeypatch.setattr(report_generator, 'REPORTS_DIR', tmp_path)
    web.app.config['TESTING'] = True
    apk = Path(os.environ['MAS_TEST_APK'])
    with web.app.test_client() as client:
        response = client.post('/upload', data={'analysis_file': (io.BytesIO(apk.read_bytes()), 'sample.apk')})
        assert response.status_code == 302
        assert '/analyze?file=uploads/' in response.headers['Location']
        path = next(tmp_path.glob('*.json'))
        raw = json.loads(path.read_text())
        assert raw['apk']['package_name'] != 'unknown'
        assert raw['raw_findings']['ingestion']['status'] == 'success'
        monkeypatch.setattr(web, 'DATA_DIR', tmp_path.parent)
        name = f'{tmp_path.name}/{path.name}'
        dashboard = client.get('/analyze', query_string={'file': name})
        assert dashboard.status_code == 200
        assert raw['apk']['package_name'].encode() in dashboard.data
        report = client.get('/report', query_string={'file': name})
        assert report.status_code == 200
        assert b'Security Assessment Summary' in report.data
        assert list(tmp_path.glob('*.apk')) == []
        assert list(tmp_path.glob('*.html'))
