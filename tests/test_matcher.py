
from vulnscope.matcher import _deb_compare, _rpm_compare, _semver_compare, is_affected


class TestSemverCompare:
    def test_equal(self):
        assert _semver_compare("1.0.0", "1.0.0") == 0

    def test_less_than(self):
        assert _semver_compare("1.0.0", "2.0.0") < 0

    def test_greater_than(self):
        assert _semver_compare("2.0.0", "1.0.0") > 0

    def test_patch_comparison(self):
        assert _semver_compare("1.0.1", "1.0.2") < 0

    def test_pre_release(self):
        assert _semver_compare("1.0.0a1", "1.0.0") < 0


class TestDebCompare:
    def test_equal(self):
        assert _deb_compare("3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.15") == 0

    def test_newer_revision(self):
        assert _deb_compare("3.0.2-0ubuntu1.16", "3.0.2-0ubuntu1.15") > 0

    def test_older_upstream(self):
        assert _deb_compare("3.0.1-1", "3.0.2-1") < 0

    def test_epoch_takes_precedence(self):
        assert _deb_compare("1:1.0-1", "2.0-1") > 0
        assert _deb_compare("2.0-1", "1:1.0-1") < 0

    def test_tilde_sorts_before(self):
        assert _deb_compare("1.0~beta1", "1.0") < 0

    def test_no_revision(self):
        assert _deb_compare("1.0", "1.1") < 0


class TestRpmCompare:
    def test_equal(self):
        assert _rpm_compare("1.0-1.el8", "1.0-1.el8") == 0

    def test_newer_version(self):
        assert _rpm_compare("2.0-1", "1.9-1") > 0

    def test_epoch(self):
        assert _rpm_compare("1:1.0-1", "2.0-1") > 0

    def test_release_comparison(self):
        assert _rpm_compare("1.0-2", "1.0-1") > 0

    def test_tilde_sorts_before(self):
        assert _rpm_compare("1.0~beta", "1.0") < 0


class TestIsAffected:
    def test_semver_range_affected(self):
        ranges = [
            {
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}],
            }
        ]
        assert is_affected("1.1.0", ranges, "pypi") is True

    def test_semver_range_not_affected_after_fix(self):
        ranges = [
            {
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}],
            }
        ]
        assert is_affected("1.2.3", ranges, "pypi") is False

    def test_semver_range_not_affected_before_intro(self):
        ranges = [
            {
                "type": "SEMVER",
                "events": [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}],
            }
        ]
        assert is_affected("1.9.9", ranges, "pypi") is False

    def test_exact_version_match(self):
        ranges = [{"type": "EXACT", "versions": ["1.0.0", "1.0.1", "1.1.0"]}]
        assert is_affected("1.0.1", ranges, "pypi") is True

    def test_exact_version_no_match(self):
        ranges = [{"type": "EXACT", "versions": ["1.0.0", "1.0.1"]}]
        assert is_affected("1.0.2", ranges, "pypi") is False

    def test_deb_ecosystem_range(self):
        ranges = [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.16"}],
            }
        ]
        assert is_affected("3.0.2-0ubuntu1.15", ranges, "deb") is True
        assert is_affected("3.0.2-0ubuntu1.16", ranges, "deb") is False

    def test_zero_introduced_means_all(self):
        ranges = [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
            }
        ]
        assert is_affected("0.1.0", ranges, "pypi") is True

    def test_last_affected(self):
        ranges = [
            {
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"last_affected": "1.5.0"}],
            }
        ]
        assert is_affected("1.5.0", ranges, "pypi") is True
        assert is_affected("1.5.1", ranges, "pypi") is False

    def test_empty_ranges_returns_false(self):
        assert is_affected("1.0.0", [], "pypi") is False
