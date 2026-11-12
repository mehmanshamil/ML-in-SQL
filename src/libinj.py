"""ctypes binding to the official libinjection C library (SQLi detector).

Build the shared library first: `python tools/build_libinjection.py`.
`is_sqli(s)` returns 1 if libinjection_sqli() flags the input, else 0.
Input is passed as UTF-8 bytes, exactly as ModSecurity passes the raw value.
"""

import ctypes
import sys
from pathlib import Path

_EXT = {"win32": ".dll", "darwin": ".dylib"}.get(sys.platform, ".so")
_LIB_PATH = Path(__file__).resolve().parent.parent / "third_party" / "build" / f"libinjection{_EXT}"

_lib = ctypes.CDLL(str(_LIB_PATH))
_lib.libinjection_sqli.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
_lib.libinjection_sqli.restype = ctypes.c_int
_lib.libinjection_version.restype = ctypes.c_char_p

VERSION = _lib.libinjection_version().decode()


def sqli(s):
    """Return (result, fingerprint). result: 1 = SQLi, 0 = not, -1 = error."""
    b = s.encode("utf-8", "surrogatepass")
    fp = ctypes.create_string_buffer(8)
    r = _lib.libinjection_sqli(b, len(b), fp)
    return r, fp.value.decode("ascii", "replace")


def is_sqli(s):
    return int(sqli(s)[0] == 1)
