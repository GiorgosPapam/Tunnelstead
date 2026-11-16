"""VPNix Create. The version comes from the VERSION file shipped with every release bundle."""
from pathlib import Path


def _read_version() -> str:
    for p in (Path(__file__).resolve().parents[2] / "VERSION", Path(__file__).resolve().parents[1] / "VERSION"):
        try:
            return p.read_text().strip()
        except OSError:
            continue
    return "0.0.0"


__version__ = _read_version()
