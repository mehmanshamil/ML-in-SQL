"""Build the official libinjection C library as a shared library for ctypes.

Source: https://github.com/libinjection/libinjection, tag v4.0.1 (SHA-256 of the
GitHub tarball is pinned below). Compiled with `zig cc` from the `ziglang` pip
package, so no system compiler is needed. Only libinjection_sqli.c is built:
it is the same detector ModSecurity exposes as the @detectSQLi operator.

Usage:  python tools/build_libinjection.py
Output: third_party/build/libinjection.{dll,so,dylib}
"""

import hashlib
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

VERSION = "4.0.1"
URL = f"https://github.com/libinjection/libinjection/archive/refs/tags/v{VERSION}.tar.gz"
SHA256 = "1a7e7764615550bd70888f4a42c66bc7ecf001ca319b0d15a39cd18672db0be2"

ROOT = Path(__file__).resolve().parent.parent
TP = ROOT / "third_party"
TARBALL = TP / "dl" / f"libinjection-v{VERSION}.tar.gz"
SRC = TP / f"libinjection-{VERSION}" / "src"
EXT = {"win32": ".dll", "darwin": ".dylib"}.get(sys.platform, ".so")
OUT = TP / "build" / f"libinjection{EXT}"


def main():
    if not TARBALL.exists():
        TARBALL.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(URL, TARBALL)
    digest = hashlib.sha256(TARBALL.read_bytes()).hexdigest()
    if digest != SHA256:
        sys.exit(f"SHA-256 mismatch for {TARBALL}: {digest}")
    if not SRC.exists():
        with tarfile.open(TARBALL) as tf:
            tf.extractall(TP, filter="data")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "ziglang", "cc", "-shared", "-O2", "-fPIC",
           "-o", str(OUT), str(SRC / "libinjection_sqli.c")]
    subprocess.run(cmd, check=True)
    print(f"built {OUT}")


if __name__ == "__main__":
    main()
