"""Version comparison logic for multiple ecosystems."""



def is_affected(installed_version: str, affected_ranges: list[dict], ecosystem: str) -> bool:
    """Return True if installed_version falls within any of the affected ranges."""
    for r in affected_ranges:
        range_type = r.get("type", "")
        if range_type == "EXACT":
            versions = r.get("versions", [])
            if installed_version in versions:
                return True
        elif range_type in ("SEMVER", "ECOSYSTEM"):
            events = r.get("events", [])
            if _in_event_range(installed_version, events, ecosystem):
                return True
    return False


def _in_event_range(version: str, events: list[dict], ecosystem: str) -> bool:
    """Check if version falls within the range defined by OSV events."""
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None

    for event in events:
        if "introduced" in event:
            introduced = event["introduced"]
        if "fixed" in event:
            fixed = event["fixed"]
        if "last_affected" in event:
            last_affected = event["last_affected"]

    if introduced is None:
        return False

    # "0" means start of time
    if introduced != "0":
        if _compare_versions(version, introduced, ecosystem) < 0:
            return False

    if fixed is not None:
        if _compare_versions(version, fixed, ecosystem) >= 0:
            return False

    if last_affected is not None and fixed is None:
        if _compare_versions(version, last_affected, ecosystem) > 0:
            return False

    return True


def _compare_versions(v1: str, v2: str, ecosystem: str) -> int:
    """Return -1, 0, or 1 comparing v1 vs v2."""
    eco_lower = ecosystem.lower()
    if eco_lower == "deb":
        return _deb_compare(v1, v2)
    if eco_lower == "rpm":
        return _rpm_compare(v1, v2)
    return _semver_compare(v1, v2)


def _semver_compare(v1: str, v2: str) -> int:
    """Compare using packaging.version.Version (PEP 440 / semver-ish)."""
    try:
        from packaging.version import InvalidVersion, Version

        try:
            pv1 = Version(v1)
        except InvalidVersion:
            pv1 = None
        try:
            pv2 = Version(v2)
        except InvalidVersion:
            pv2 = None

        if pv1 is None and pv2 is None:
            return (v1 > v2) - (v1 < v2)
        if pv1 is None:
            return 1
        if pv2 is None:
            return -1

        if pv1 < pv2:
            return -1
        if pv1 > pv2:
            return 1
        return 0
    except Exception:
        return (v1 > v2) - (v1 < v2)


def _deb_parse_epoch(version: str) -> tuple[int, str]:
    """Split epoch from a Debian version string."""
    if ":" in version:
        epoch_str, _, rest = version.partition(":")
        try:
            return int(epoch_str), rest
        except ValueError:
            pass
    return 0, version


def _deb_parse(version: str) -> tuple[int, str, str]:
    """Parse Debian version into (epoch, upstream, revision)."""
    epoch, rest = _deb_parse_epoch(version)
    if "-" in rest:
        last_dash = rest.rfind("-")
        upstream = rest[:last_dash]
        revision = rest[last_dash + 1 :]
    else:
        upstream = rest
        revision = "0"
    return epoch, upstream, revision


def _deb_char_order(c: str) -> int:
    """Ordering for Debian non-digit character comparison (Debian policy).

    ~ sorts before everything (including end-of-string).
    End-of-string (empty) sorts after ~ and before any non-letter.
    Letters sort by ASCII value.
    Other characters sort after letters.
    """
    if c == "~":
        return -1
    if not c:
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_compare_segment(a: str, b: str) -> int:
    """Compare two Debian version segments using the dpkg ordering rules."""
    i, j = 0, 0
    la, lb = len(a), len(b)

    while i < la or j < lb:
        # Compare non-digit portions character by character
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = a[i] if i < la else ""
            bc = b[j] if j < lb else ""

            if ac == bc:
                if ac:
                    i += 1
                if bc:
                    j += 1
                if not ac and not bc:
                    break
                continue

            oa, ob = _deb_char_order(ac), _deb_char_order(bc)
            if oa != ob:
                return -1 if oa < ob else 1
            if ac:
                i += 1
            if bc:
                j += 1

        # Compare digit portions numerically
        ai = i
        while i < la and a[i].isdigit():
            i += 1
        bj = j
        while j < lb and b[j].isdigit():
            j += 1

        na = int(a[ai:i]) if i > ai else 0
        nb = int(b[bj:j]) if j > bj else 0
        if na < nb:
            return -1
        if na > nb:
            return 1

    return 0


def _deb_compare(v1: str, v2: str) -> int:
    e1, u1, r1 = _deb_parse(v1)
    e2, u2, r2 = _deb_parse(v2)

    if e1 != e2:
        return -1 if e1 < e2 else 1

    c = _deb_compare_segment(u1, u2)
    if c != 0:
        return c

    return _deb_compare_segment(r1, r2)


def _rpmvercmp(a: str, b: str) -> int:
    """Implement the RPM version comparison algorithm."""
    if a == b:
        return 0

    i, j = 0, 0
    la, lb = len(a), len(b)

    while i < la or j < lb:
        # Skip non-alphanumeric/non-tilde characters
        while i < la and not a[i].isalnum() and a[i] != "~":
            i += 1
        while j < lb and not b[j].isalnum() and b[j] != "~":
            j += 1

        # Handle tilde (sorts before everything)
        if i < la and a[i] == "~" or j < lb and b[j] == "~":
            if i >= la or a[i] != "~":
                return 1
            if j >= lb or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue

        if i >= la and j >= lb:
            return 0
        if i >= la:
            return -1
        if j >= lb:
            return 1

        # Extract numeric or alpha segment
        if a[i].isdigit():
            seg_a = ""
            while i < la and a[i].isdigit():
                seg_a += a[i]
                i += 1
            seg_b = ""
            while j < lb and b[j].isdigit():
                seg_b += b[j]
                j += 1
            # Numeric comparison
            ia, ib = int(seg_a) if seg_a else 0, int(seg_b) if seg_b else 0
            if ia < ib:
                return -1
            if ia > ib:
                return 1
        else:
            seg_a = ""
            while i < la and a[i].isalpha():
                seg_a += a[i]
                i += 1
            seg_b = ""
            while j < lb and b[j].isalpha():
                seg_b += b[j]
                j += 1
            if not seg_b:
                return 1
            if not seg_a:
                return -1
            if seg_a < seg_b:
                return -1
            if seg_a > seg_b:
                return 1

    return 0


def _rpm_compare(v1: str, v2: str) -> int:
    """Compare RPM versions (EPOCH:VERSION-RELEASE format)."""

    def parse_rpm(v: str) -> tuple[int, str, str]:
        epoch = 0
        if ":" in v:
            ep_str, _, rest = v.partition(":")
            try:
                epoch = int(ep_str)
            except ValueError:
                rest = v
        else:
            rest = v

        if "-" in rest:
            version, _, release = rest.rpartition("-")
        else:
            version, release = rest, ""

        return epoch, version, release

    e1, ver1, rel1 = parse_rpm(v1)
    e2, ver2, rel2 = parse_rpm(v2)

    if e1 != e2:
        return -1 if e1 < e2 else 1

    c = _rpmvercmp(ver1, ver2)
    if c != 0:
        return c

    if rel1 and rel2:
        return _rpmvercmp(rel1, rel2)
    return 0
