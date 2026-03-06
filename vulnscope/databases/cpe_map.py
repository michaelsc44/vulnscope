"""Maps installed package names to NVD CPE (vendor, product) pairs.

Used to query NVD for vulnerabilities in software that OSV.dev doesn't cover
well — primarily vendor-distributed applications like Chrome, VS Code, Slack, etc.
"""

import re

# Maps lowercase package name -> (cpe_vendor, cpe_product)
# Covers both dpkg package names and snap names.
CPE_MAP: dict[str, tuple[str, str]] = {
    # Browsers
    "google-chrome-stable": ("google", "chrome"),
    "google-chrome-beta": ("google", "chrome"),
    "google-chrome-unstable": ("google", "chrome"),
    "chromium-browser": ("google", "chrome"),
    "chromium": ("chromium", "chromium"),
    "firefox": ("mozilla", "firefox"),
    "firefox-esr": ("mozilla", "firefox"),
    "opera-stable": ("opera", "opera_browser"),
    "opera-beta": ("opera", "opera_browser"),
    "brave-browser": ("brave", "brave"),
    "microsoft-edge-stable": ("microsoft", "edge"),
    "microsoft-edge-beta": ("microsoft", "edge"),
    "vivaldi-stable": ("vivaldi", "vivaldi"),
    # IDEs / editors
    "code": ("microsoft", "visual_studio_code"),
    "code-insiders": ("microsoft", "visual_studio_code"),
    "atom": ("github", "atom"),
    "sublime-text": ("sublimehq", "sublime_text"),
    "intellij-idea-community": ("jetbrains", "intellij_idea"),
    "intellij-idea-ultimate": ("jetbrains", "intellij_idea"),
    "pycharm-community": ("jetbrains", "pycharm"),
    "pycharm-professional": ("jetbrains", "pycharm"),
    # Communication
    "slack-desktop": ("slack", "slack"),
    "zoom": ("zoom", "zoom_meetings"),
    "discord": ("discord", "discord"),
    "signal-desktop": ("signal", "signal"),
    "teams-for-linux": ("microsoft", "teams"),
    "skype": ("microsoft", "skype"),
    "skypeforlinux": ("microsoft", "skype"),
    "mattermost-desktop": ("mattermost", "mattermost_desktop"),
    "element-desktop": ("vector_im", "element"),
    # Productivity / utilities
    "spotify": ("spotify", "spotify"),
    "1password": ("agilebits", "1password"),
    "bitwarden": ("bitwarden", "bitwarden"),
    "dropbox": ("dropbox", "dropbox"),
    "steam": ("valvesoftware", "steam"),
    "virtualbox": ("oracle", "vm_virtualbox"),
    "docker-ce": ("docker", "docker"),
    "docker-desktop": ("docker", "docker_desktop"),
    # Media
    "vlc": ("videolan", "vlc_media_player"),
    "gimp": ("gimp", "gimp"),
    "inkscape": ("inkscape", "inkscape"),
    "obs-studio": ("obsproject", "obs_studio"),
    # Security / networking tools
    "wireshark": ("wireshark", "wireshark"),
    "nmap": ("nmap", "nmap"),
    "burpsuite": ("portswigger", "burp_suite"),
    # Runtime environments (when installed as standalone apps)
    "nodejs": ("nodejs", "node.js"),
    "openjdk-17-jre": ("oracle", "jre"),
    "openjdk-21-jre": ("oracle", "jre"),
}


def get_cpe_mapping(package_name: str) -> tuple[str, str] | None:
    """Return (cpe_vendor, cpe_product) for the given package name, or None."""
    return CPE_MAP.get(package_name.lower())


def clean_version_for_cpe(version: str, ecosystem: str) -> str:
    """Strip ecosystem-specific suffixes to get a bare version number for CPE queries.

    Examples:
      "144.0.7559.132-1"  (deb)  -> "144.0.7559.132"
      "148.0-1"           (snap) -> "148.0"
      "7.95"              (snap) -> "7.95"
    """
    if ecosystem in ("deb", "snap"):
        # Remove Debian/snap release suffix (trailing -N or -Nubuntu...)
        version = re.split(r"-\d", version)[0]
    return version
