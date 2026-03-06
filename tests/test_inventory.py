import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from vulnscope.inventory.dpkg import DpkgCollector
from vulnscope.inventory.flatpak import FlatpakCollector
from vulnscope.inventory.os_info import OSInfo, _parse_os_release, get_os_info
from vulnscope.inventory.pip_packages import PipCollector
from vulnscope.inventory.snap import SnapCollector

FIXTURES = Path(__file__).parent / "fixtures"


class TestOsReleaseParsing:
    def test_parses_ubuntu(self):
        content = """
PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
VERSION_CODENAME=jammy
"""
        result = _parse_os_release(content)
        assert result["ID"] == "ubuntu"
        assert result["VERSION_ID"] == "22.04"
        assert result["VERSION_CODENAME"] == "jammy"
        assert result["NAME"] == "Ubuntu"

    def test_strips_quotes(self):
        content = 'PRETTY_NAME="Ubuntu 22.04"\nID=ubuntu\n'
        result = _parse_os_release(content)
        assert result["PRETTY_NAME"] == "Ubuntu 22.04"

    def test_ignores_comments(self):
        content = "# comment\nID=fedora\n"
        result = _parse_os_release(content)
        assert "# comment" not in result
        assert result["ID"] == "fedora"

    def test_get_os_info_returns_osinfo(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="6.5.0-44-generic\n")
            with patch("pathlib.Path.exists", return_value=True), patch(
                "pathlib.Path.read_text",
                return_value='ID=ubuntu\nNAME="Ubuntu"\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04 LTS"\nVERSION_CODENAME=jammy\n',
            ):
                info = get_os_info()
                assert isinstance(info, OSInfo)
                assert info.id == "ubuntu"


class TestDpkgCollector:
    def test_parses_fixture_output(self):
        fixture = (FIXTURES / "dpkg_output.txt").read_text()
        with patch("shutil.which", return_value="/usr/bin/dpkg-query"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = DpkgCollector(distro_id="ubuntu")
                packages = collector.collect()

        # broken-pkg should be filtered out
        names = [p.name for p in packages]
        assert "openssl" in names
        assert "curl" in names
        assert "broken-pkg" not in names

    def test_correct_purl_format(self):
        fixture = "openssl\t3.0.2-0ubuntu1.15\tamd64\tinstall ok installed\n"
        with patch("shutil.which", return_value="/usr/bin/dpkg-query"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = DpkgCollector(distro_id="ubuntu")
                packages = collector.collect()

        assert len(packages) == 1
        assert packages[0].purl == "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?arch=amd64"
        assert packages[0].ecosystem == "deb"
        assert packages[0].source == "dpkg"

    def test_unavailable_returns_empty(self):
        with patch("shutil.which", return_value=None):
            collector = DpkgCollector()
            assert collector.is_available() is False
            assert collector.collect() == []

    def test_subprocess_failure_returns_empty(self):
        with patch("shutil.which", return_value="/usr/bin/dpkg-query"):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                collector = DpkgCollector()
                assert collector.collect() == []


class TestFlatpakCollector:
    def test_parses_flatpak_output(self):
        fixture = (
            "Firefox\torg.mozilla.firefox\t128.0\tstable\n"
            "GIMP\torg.gimp.GIMP\t2.10.36\tstable\n"
        )
        with patch("shutil.which", return_value="/usr/bin/flatpak"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = FlatpakCollector()
                packages = collector.collect()

        names = [p.name for p in packages]
        assert "Firefox" in names
        assert "GIMP" in names
        assert len(packages) == 2

    def test_correct_purl_format(self):
        fixture = "Firefox\torg.mozilla.firefox\t128.0\tstable\n"
        with patch("shutil.which", return_value="/usr/bin/flatpak"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = FlatpakCollector()
                packages = collector.collect()

        assert len(packages) == 1
        assert packages[0].purl == "pkg:flatpak/org.mozilla.firefox@128.0"
        assert packages[0].ecosystem == "flatpak"
        assert packages[0].source == "flatpak"

    def test_skips_entries_without_version(self):
        fixture = "SomeRuntime\torg.freedesktop.Platform\t\tstable\n"
        with patch("shutil.which", return_value="/usr/bin/flatpak"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = FlatpakCollector()
                packages = collector.collect()

        assert len(packages) == 0

    def test_unavailable_returns_empty(self):
        with patch("shutil.which", return_value=None):
            collector = FlatpakCollector()
            assert collector.is_available() is False
            assert collector.collect() == []

    def test_subprocess_failure_returns_empty(self):
        with patch("shutil.which", return_value="/usr/bin/flatpak"):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                collector = FlatpakCollector()
                assert collector.collect() == []


class TestPipCollector:
    def test_parses_pip_json(self):
        fixture = (FIXTURES / "pip_output.json").read_text()
        with patch("shutil.which", return_value="/usr/bin/python3"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = PipCollector()
                packages = collector.collect()

        names = [p.name for p in packages]
        assert "requests" in names
        assert "cryptography" in names

    def test_correct_purl_format(self):
        fixture = json.dumps([{"name": "requests", "version": "2.31.0"}])
        with patch("shutil.which", return_value="/usr/bin/python3"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = PipCollector()
                packages = collector.collect()

        assert len(packages) == 1
        assert packages[0].purl == "pkg:pypi/requests@2.31.0"
        assert packages[0].ecosystem == "pypi"

    def test_deduplicates_across_interpreters(self):
        fixture = json.dumps([{"name": "pip", "version": "23.0"}])
        # is_available() calls which("python3") once (short-circuits on success),
        # then _get_interpreters() calls which("python3") + which("python") = 3 total
        with patch("shutil.which", side_effect=[
            "/usr/bin/python3",   # is_available() -> found
            "/usr/bin/python3",   # _get_interpreters() -> python3
            "/usr/bin/python",    # _get_interpreters() -> python (different path)
        ]):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = PipCollector()
                packages = collector.collect()

        assert len(packages) == 1

    def test_unavailable_returns_empty(self):
        with patch("shutil.which", return_value=None):
            collector = PipCollector()
            assert collector.is_available() is False
            assert collector.collect() == []


class TestSnapCollector:
    def test_parses_fixture_output(self):
        fixture = (FIXTURES / "snap_output.txt").read_text()
        with patch("shutil.which", return_value="/usr/bin/snap"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = SnapCollector()
                packages = collector.collect()

        names = [p.name for p in packages]
        assert "firefox" in names
        assert "vlc" in names
        assert "chromium" in names

    def test_filters_base_snaps(self):
        fixture = (FIXTURES / "snap_output.txt").read_text()
        with patch("shutil.which", return_value="/usr/bin/snap"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = SnapCollector()
                packages = collector.collect()

        names = [p.name for p in packages]
        assert "bare" not in names
        assert "core22" not in names
        assert "snapd" not in names
        assert "gtk-common-themes" not in names

    def test_correct_purl_and_ecosystem(self):
        fixture = (FIXTURES / "snap_output.txt").read_text()
        with patch("shutil.which", return_value="/usr/bin/snap"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=fixture)
                collector = SnapCollector()
                packages = collector.collect()

        firefox = next(p for p in packages if p.name == "firefox")
        assert firefox.purl == "pkg:snap/firefox@128.0-2"
        assert firefox.ecosystem == "snap"
        assert firefox.source == "snap"

    def test_unavailable_returns_empty(self):
        with patch("shutil.which", return_value=None):
            collector = SnapCollector()
            assert collector.is_available() is False
            assert collector.collect() == []

    def test_timeout_returns_empty(self):
        import subprocess

        with patch("shutil.which", return_value="/usr/bin/snap"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("snap", 15)):
                collector = SnapCollector()
                assert collector.collect() == []

    def test_file_not_found_returns_empty(self):
        with patch("shutil.which", return_value="/usr/bin/snap"):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                collector = SnapCollector()
                assert collector.collect() == []
