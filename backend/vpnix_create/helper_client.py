"""Client for the privileged helper (JSON line protocol over a Unix socket). The API never runs commands."""
import json
import socket

from .config import get_settings


class HelperError(RuntimeError):
    pass


class Helper:
    def __init__(self, path: str | None = None, timeout: float = 30.0):
        self.path, self.timeout = path or get_settings().helper_socket, timeout

    def call(self, method: str, **params):
        if not hasattr(socket, "AF_UNIX"):
            raise HelperError("The privileged helper is only available on Linux")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.path)
                s.sendall(json.dumps({"method": method, "params": params}).encode() + b"\n")
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as e:
            raise HelperError(f"System helper unavailable: {e}") from None
        resp = json.loads(buf or b"{}")
        if "error" in resp:
            raise HelperError(resp["error"])
        return resp.get("result")


def get_helper():
    """FastAPI dependency (overridden in tests)."""
    from . import testing
    if testing.enabled():
        return testing.SimulatedHost()
    return Helper()
