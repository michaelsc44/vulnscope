"""Kernel livepatch detection for canonical-livepatch (Ubuntu) and kpatch (RHEL/Fedora)."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class LivepatchStatus:
    available: bool
    backend: str | None  # "canonical-livepatch" or "kpatch"
    enabled: bool = False
    applied_patches: list[dict[str, str]] = field(default_factory=list)
    raw_output: str = ""


def detect_livepatch(*, runner: object | None = None) -> LivepatchStatus:
    """Detect if a livepatch system is available and report its status."""
    status = _check_canonical_livepatch(runner=runner)
    if status.available:
        return status

    return _check_kpatch(runner=runner)


def _run_command(
    args: list[str], *, runner: object | None = None
) -> subprocess.CompletedProcess[str] | None:
    try:
        if runner is not None:
            return runner(args)  # type: ignore[operator]
        return subprocess.run(
            args, capture_output=True, text=True, timeout=10
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _check_canonical_livepatch(*, runner: object | None = None) -> LivepatchStatus:
    if runner is None and not shutil.which("canonical-livepatch"):
        return LivepatchStatus(available=False, backend=None)

    cp = _run_command(["canonical-livepatch", "status"], runner=runner)
    if cp is None:
        return LivepatchStatus(available=False, backend=None)
    if cp.returncode != 0:
        return LivepatchStatus(
            available=True,
            backend="canonical-livepatch",
            enabled=False,
            raw_output=cp.stderr if cp else "",
        )

    output = cp.stdout
    patches = _parse_canonical_livepatch_output(output)

    return LivepatchStatus(
        available=True,
        backend="canonical-livepatch",
        enabled=True,
        applied_patches=patches,
        raw_output=output,
    )


def _parse_canonical_livepatch_output(output: str) -> list[dict[str, str]]:
    patches: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current:
                patches.append(current)
                current = {}
            continue

        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            value = value.strip()
            if key and value:
                current[key] = value

    if current:
        patches.append(current)

    return patches


def _check_kpatch(*, runner: object | None = None) -> LivepatchStatus:
    if runner is None and not shutil.which("kpatch"):
        return LivepatchStatus(available=False, backend=None)

    cp = _run_command(["kpatch", "list"], runner=runner)
    if cp is None:
        return LivepatchStatus(available=False, backend=None)

    output = cp.stdout if cp.returncode == 0 else ""
    patches = _parse_kpatch_output(output)

    return LivepatchStatus(
        available=True,
        backend="kpatch",
        enabled=cp.returncode == 0,
        applied_patches=patches,
        raw_output=output,
    )


def _parse_kpatch_output(output: str) -> list[dict[str, str]]:
    patches: list[dict[str, str]] = []

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Loaded") or line.startswith("Installed"):
            continue
        parts = line.split()
        if parts:
            patch: dict[str, str] = {"name": parts[0]}
            if len(parts) > 1:
                patch["status"] = " ".join(parts[1:])
            patches.append(patch)

    return patches
