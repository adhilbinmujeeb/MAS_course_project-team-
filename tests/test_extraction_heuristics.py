"""
Tests for the extraction heuristics that were corrected after scanning real
applications (see the notes in each module for the measurements).

These are unit tests on the patterns and thresholds themselves; the
end-to-end effect is covered by the pipeline and scoring suites.
"""

from feature_extraction.obfuscation_heuristics import (
    MIN_ENTROPY_FINDINGS, suspected_string_encryption,
)
from feature_extraction.sensitive_apis import SENSITIVE_APIS
from feature_extraction.string_extraction import IP_RE


class TestIpExtraction:

    def test_object_identifiers_are_not_ips(self):
        """
        X.509/ASN.1 object identifiers are dotted decimal runs and used to be
        reported as IP addresses -- one real APK produced 141 of them.
        """
        assert IP_RE.findall("1.3.6.1.4.1.44") == []
        assert IP_RE.findall("1.2.156.197.1") == []
        assert IP_RE.findall("1.9.16.3.6") == []

    def test_a_longer_dotted_run_yields_nothing(self):
        assert IP_RE.findall("1.1.1.1.1") == []
        assert IP_RE.findall("10.0.0.1.2") == []

    def test_real_addresses_are_still_found(self):
        assert IP_RE.findall("45.133.201.88") == ["45.133.201.88"]
        assert IP_RE.findall("connect to 185.220.101.44 now") == ["185.220.101.44"]

    def test_addresses_inside_urls_are_still_found(self):
        assert IP_RE.findall("http://45.133.201.88/gate.php") == ["45.133.201.88"]


class TestSensitiveApiPatterns:

    def test_base_class_loader_is_not_dynamic_code_loading(self):
        """
        ClassLoader.loadClass is the standard class-resolution path, so it
        flagged nearly every real application, including FOSS ones.
        """
        patterns = SENSITIVE_APIS["dynamic_code_loading"]
        assert not any("ClassLoader; loadClass" in pattern for pattern in patterns)

    def test_file_backed_loaders_are_still_detected(self):
        patterns = " ".join(SENSITIVE_APIS["dynamic_code_loading"])
        assert "DexClassLoader;" in patterns
        assert "PathClassLoader;" in patterns
        assert "InMemoryDexClassLoader;" in patterns

    def test_the_other_categories_are_untouched(self):
        assert "Runtime; exec" in SENSITIVE_APIS["shell_and_process_exec"]
        assert "SmsManager; sendTextMessage" in SENSITIVE_APIS["sms_fraud"]


class TestStringEncryptionSuspicion:

    def test_an_empty_pool_is_never_suspicious(self):
        assert suspected_string_encryption(0, 0) is False

    def test_a_handful_of_blobs_is_not_suspicious(self):
        """Measured: a FOSS notes app produced 4 of 22,586 strings (0.02%)."""
        assert suspected_string_encryption(4, 22586) is False

    def test_a_large_count_in_a_huge_pool_is_not_suspicious(self):
        """Measured: the F-Droid client produced 1,184 of 122,586 (0.97%)."""
        assert suspected_string_encryption(1184, 122586) is False

    def test_below_the_absolute_floor_is_not_suspicious(self):
        assert suspected_string_encryption(MIN_ENTROPY_FINDINGS - 1, 100) is False

    def test_many_blobs_dominating_a_small_pool_is_suspicious(self):
        assert suspected_string_encryption(200, 2000) is True

    def test_the_ratio_and_the_floor_both_have_to_hold(self):
        # Plenty of blobs, but they are a negligible share of the pool.
        assert suspected_string_encryption(50, 1_000_000) is False
