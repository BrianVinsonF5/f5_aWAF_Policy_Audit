"""
Unit tests for src/policy_comparator.py

Uses the baseline and drifted fixture XMLs to verify the diff engine
detects the known set of differences documented in target_policy_drifted.xml.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.policy_parser import parse_policy, get_policy_metadata
from src.policy_comparator import (
    compare_policies,
    ComparisonResult,
    DiffItem,
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    SEVERITY_INFO,
)

FIXTURES = Path(__file__).parent / "fixtures"
BASELINE = str(FIXTURES / "baseline_policy.xml")
DRIFTED  = str(FIXTURES / "target_policy_drifted.xml")


@pytest.fixture(scope="module")
def result() -> ComparisonResult:
    baseline_data = parse_policy(BASELINE)
    target_data   = parse_policy(DRIFTED)
    meta          = get_policy_metadata(DRIFTED)
    return compare_policies(
        baseline=baseline_data,
        target=target_data,
        policy_meta=meta,
        baseline_name="baseline_policy.xml",
    )


# ── Result structure ───────────────────────────────────────────────────────────

class TestComparisonResultStructure:
    def test_returns_comparison_result(self, result):
        assert isinstance(result, ComparisonResult)

    def test_policy_name_set(self, result):
        assert result.policy_name == "target_policy_drifted"

    def test_baseline_name_set(self, result):
        assert result.baseline_name == "baseline_policy.xml"

    def test_timestamp_set(self, result):
        assert result.timestamp  # non-empty

    def test_score_between_0_and_100(self, result):
        assert 0.0 <= result.score <= 100.0

    def test_summary_keys(self, result):
        assert "by_section" in result.summary
        assert "totals" in result.summary

    def test_diffs_is_list(self, result):
        assert isinstance(result.diffs, list)
        assert len(result.diffs) > 0


# ── Critical findings ──────────────────────────────────────────────────────────

class TestCriticalFindings:
    @pytest.fixture(autouse=True)
    def setup(self, result):
        self.criticals = [d for d in result.diffs if d.severity == SEVERITY_CRITICAL]
        self.critical_keys = {
            (d.section, d.element_name, d.attribute) for d in self.criticals
        }

    def test_enforcement_mode_critical(self):
        assert ("general", "enforcementMode", "enforcementMode") in self.critical_keys

    def test_viol_cookie_block_critical(self):
        assert any(
            d.element_name == "VIOL_ASM_COOKIE_MODIFIED" and d.attribute == "block"
            for d in self.criticals
        )

    def test_sig_470_disabled_critical(self):
        assert any(
            d.section == "attack-signatures"
            and d.element_name == "200001470"
            and d.attribute == "enabled"
            for d in self.criticals
        )

    def test_data_guard_disabled_critical(self):
        assert any(
            d.section == "data-guard" and d.attribute == "enabled"
            for d in self.criticals
        )

    def test_bot_defense_disabled_critical(self):
        assert any(
            d.section == "bot-defense" and d.attribute == "enabled"
            for d in self.criticals
        )

    def test_sql_sig_set_block_critical(self):
        # Per spec: "Flag sets where block state differs as CRITICAL"
        assert any(
            d.section == "signature-sets"
            and "SQL" in d.element_name
            and d.attribute == "block"
            for d in self.criticals
        )

    def test_at_least_5_criticals(self):
        assert len(self.criticals) >= 5


# ── Warning findings ───────────────────────────────────────────────────────────

class TestWarningFindings:
    @pytest.fixture(autouse=True)
    def setup(self, result):
        self.warnings = [d for d in result.diffs if d.severity == SEVERITY_WARNING]

    def test_url_login_sig_check_warning(self):
        # /login URL attackSignaturesCheck=false is a WARNING
        assert any(
            d.section == "urls"
            and d.element_name == "/login"
            and d.attribute == "attackSignaturesCheck"
            for d in self.warnings
        )

    def test_sig_471_staging_warning(self):
        assert any(
            d.section == "attack-signatures"
            and d.element_name == "200001471"
            and d.attribute == "performStaging"
            for d in self.warnings
        )

    def test_login_url_attack_sig_check_warning(self):
        assert any(
            d.section == "urls"
            and d.element_name == "/login"
            and d.attribute == "attackSignaturesCheck"
            for d in self.warnings
        )

    def test_extra_whitelist_ip_warning(self):
        assert any(
            d.section == "whitelist-ips" and "192.168.99.99" in d.element_name
            for d in self.warnings
        )


# ── Info findings ──────────────────────────────────────────────────────────────

class TestInfoFindings:
    @pytest.fixture(autouse=True)
    def setup(self, result):
        self.infos = [d for d in result.diffs if d.severity == SEVERITY_INFO]

    def test_missing_baseline_ip_info(self):
        # 10.0.0.1 is in baseline whitelist but not target → INFO
        assert any(
            d.section == "whitelist-ips" and "10.0.0.1" in d.element_name
            for d in self.infos
        )


# ── Compliance score ───────────────────────────────────────────────────────────

class TestComplianceScore:
    def test_score_below_pass_threshold(self, result):
        # Drifted policy has many criticals → must score < 90
        assert result.score < 90.0

    def test_score_decreases_with_criticals(self):
        # Construct a minimal comparison with known diffs
        from src.policy_comparator import _calculate_score, DiffItem
        diffs = [
            DiffItem("s", "e", "a", True, False, SEVERITY_CRITICAL, ""),
            DiffItem("s", "e2", "a", True, False, SEVERITY_CRITICAL, ""),
        ]
        score = _calculate_score(diffs)
        assert score == 90.0  # 100 - 2*5

    def test_perfect_score_for_identical_policies(self):
        baseline_data = parse_policy(BASELINE)
        target_data   = parse_policy(BASELINE)   # same file
        meta          = get_policy_metadata(BASELINE)
        r = compare_policies(baseline_data, target_data, meta, "baseline.xml")
        assert r.score == 100.0
        assert r.diffs == []

    def test_score_floor_at_zero(self):
        from src.policy_comparator import _calculate_score, DiffItem
        diffs = [
            DiffItem("s", str(i), "a", True, False, SEVERITY_CRITICAL, "")
            for i in range(30)
        ]
        score = _calculate_score(diffs)
        assert score == 0.0


# ── Extra / missing tracking ───────────────────────────────────────────────────

class TestExtraMissing:
    def test_extra_whitelist_in_extra_list(self, result):
        extra_ips = [
            item for item in result.extra_in_target
            if item.get("section") == "whitelist-ips"
        ]
        assert any("192.168.99.99" in str(item) for item in extra_ips)

    def test_missing_whitelist_in_missing_list(self, result):
        missing_ips = [
            item for item in result.missing_in_target
            if item.get("section") == "whitelist-ips"
        ]
        assert any("10.0.0.1" in str(item) for item in missing_ips)
