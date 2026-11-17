#!/usr/bin/env python3
"""Build and sign a Tunnelstead release bundle (maintainers only).

    python tools/release.py keygen  --key ~/.tunnelstead/release-signing.key   # once; prints the public key
    python tools/release.py build   --key ~/.tunnelstead/release-signing.key [--version X.Y.Z] [--out dist]

The bundle is `tunnelstead-X.Y.Z.tar.gz` (source + built web UI + VERSION) with `tunnelstead-X.Y.Z.tar.gz.sig`.
The Ed25519 signature covers "tunnelstead-release:<version>:<sha256 of the bundle>", so a signed old bundle can
never be passed off as a newer version. The private key must never be committed or uploaded anywhere.
"""
import argparse
import base64
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def message(version: str, sha256: str) -> bytes:
    return f"tunnelstead-release:{version}:{sha256}".encode()


def load_key(path: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(path).expanduser().read_text().strip()))


def keygen(path: str) -> None:
    p = Path(path).expanduser()
    if p.exists():
        sys.exit(f"{p} already exists; refusing to overwrite a signing key")
    p.parent.mkdir(parents=True, exist_ok=True)
    k = Ed25519PrivateKey.generate()
    raw = k.private_bytes_raw()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(raw).decode() + "\n")
    pub = base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    (ROOT / "installer" / "release-key.pub").write_text(pub + "\n")
    print(f"Private key: {p}  (keep it secret and backed up)\nPublic key written to installer/release-key.pub: {pub}")


def build(key: str, version: str | None, out: str, replace: dict | None = None) -> Path:
    version = version or (ROOT / "VERSION").read_text().strip()
    if not VERSION_RE.match(version):
        sys.exit("version must be X.Y.Z")
    if not (ROOT / "frontend" / "dist" / "index.html").exists():
        sys.exit("frontend/dist is missing: run npm run build in frontend/ first")
    src = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar", "HEAD"], capture_output=True, check=True).stdout
    buf, prefix = io.BytesIO(), f"tunnelstead-{version}/"
    with tarfile.open(fileobj=buf, mode="w:gz") as out_tar, tarfile.open(fileobj=io.BytesIO(src)) as git_tar:
        for m in git_tar.getmembers():
            if m.name == "VERSION":
                continue
            f = git_tar.extractfile(m) if m.isfile() else None
            if replace and m.name in replace:  # testing only: e.g. a deliberately failing installer
                data = Path(replace[m.name]).read_bytes()
                f, m.size = io.BytesIO(data), len(data)
            m.name = prefix + m.name
            out_tar.addfile(m, f)
        for p in sorted((ROOT / "frontend" / "dist").rglob("*")):
            if p.is_file():
                out_tar.add(p, prefix + p.relative_to(ROOT).as_posix())
        data = (version + "\n").encode()
        info = tarfile.TarInfo(prefix + "VERSION")
        info.size, info.mode = len(data), 0o644
        out_tar.addfile(info, io.BytesIO(data))
    blob = buf.getvalue()
    digest = hashlib.sha256(blob).hexdigest()
    sig = load_key(key).sign(message(version, digest))
    d = Path(out)
    d.mkdir(parents=True, exist_ok=True)
    bundle = d / f"tunnelstead-{version}.tar.gz"
    bundle.write_bytes(blob)
    (d / f"{bundle.name}.sig").write_text(base64.b64encode(sig).decode() + "\n")
    print(f"{bundle}  sha256={digest}")
    return bundle


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--key", required=True)
    b = sub.add_parser("build")
    b.add_argument("--key", required=True)
    b.add_argument("--version")
    b.add_argument("--out", default="dist")
    b.add_argument("--replace", action="append", default=[], metavar="PATH=LOCALFILE",
                   help="testing only: substitute a file in the bundle (e.g. a failing installer)")
    a = ap.parse_args()
    if a.cmd == "keygen":
        keygen(a.key)
    else:
        build(a.key, a.version, a.out, dict(r.split("=", 1) for r in a.replace))
