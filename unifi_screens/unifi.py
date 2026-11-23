"""UniFi Network + Connect clients with TOFU certificate pinning.

Every connection asserts the pinned SHA-256 fingerprint of the console's
certificate during the TLS handshake, so a mismatch fails before any request
byte (API key, password, cookie) is sent. Redirects are never followed.

The destructive calls (:meth:`NetworkClient.power_cycle`,
:meth:`ConnectClient.action`) refuse unless ``executor.LIVE_ACTIONS_ALLOWED``.
"""
import hashlib
import re
import socket
import ssl
import time
import warnings
from urllib.parse import quote, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

TIMEOUT = (5, 15)  # connect, read
BACKOFF_MIN_S, BACKOFF_MAX_S = 30, 900
MAX_LOGINS, LOGIN_WINDOW_S = 3, 600

warnings.filterwarnings("ignore", category=InsecureRequestWarning)


class UnifiError(Exception):
    """``kind``: config, unreachable, pin, auth, rate_limited, not_found, bad_response."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class LiveActionsDisabled(UnifiError):
    def __init__(self):
        super().__init__("disabled", "live actions are disabled in this version")


def _require_live():
    from . import executor

    if not executor.LIVE_ACTIONS_ALLOWED:
        raise LiveActionsDisabled()


def origin(url):
    """``(host, port)`` of an https console URL; raises ``UnifiError('config')``."""
    parts = urlsplit((url or "").strip())
    if parts.scheme != "https" or not parts.hostname:
        raise UnifiError("config", "the console URL must start with https://")
    return parts.hostname, parts.port or 443


def fetch_fingerprint(url, timeout=5):
    """SHA-256 (hex) of the certificate the console presents right now. Sends nothing else."""
    host, port = origin(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as exc:
        raise UnifiError("unreachable", f"{host}:{port}: {exc}") from None
    return hashlib.sha256(der).hexdigest()


def pretty_fingerprint(fp):
    return ":".join(fp[i:i + 2] for i in range(0, len(fp or ""), 2)).upper()


class PinnedAdapter(HTTPAdapter):
    """No CA check, but the certificate must hash to ``fingerprint`` (checked in the handshake)."""

    def __init__(self, fingerprint, **kwargs):
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint or ""):
            raise UnifiError("pin", "no trusted certificate fingerprint")
        self.fingerprint = fingerprint
        super().__init__(max_retries=0, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["assert_fingerprint"] = self.fingerprint
        pool_kwargs["cert_reqs"] = "CERT_NONE"
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


class _Refuse(HTTPAdapter):
    def send(self, request, **kwargs):
        raise requests.exceptions.InvalidURL(f"refusing to contact {request.url}: not the pinned console")


class _Client:
    def __init__(self, url, fingerprint, *, clock=time.monotonic):
        self.host, self.port = origin(url)
        self.base = f"https://{self.host}:{self.port}"
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.mount("https://", _Refuse())
        self.session.mount("http://", _Refuse())
        self.session.mount(self.base + "/", PinnedAdapter(fingerprint))
        self._clock = clock
        self._backoff_until = 0.0
        self._backoff_s = 0

    def _request(self, method, path, **kwargs):
        if self._clock() < self._backoff_until:
            raise UnifiError("rate_limited", "backing off after HTTP 429")
        try:
            resp = self.session.request(method, self.base + path, timeout=TIMEOUT,
                                        allow_redirects=False, verify=False, **kwargs)
        except requests.exceptions.SSLError as exc:
            if "fingerprint" in str(exc).lower():
                raise UnifiError("pin", "certificate does not match the trusted fingerprint") from None
            raise UnifiError("unreachable", f"TLS error: {exc}") from None
        except requests.RequestException as exc:
            raise UnifiError("unreachable", str(exc)) from None
        if resp.status_code == 429:
            self._backoff_s = min(max(self._backoff_s * 2, BACKOFF_MIN_S), BACKOFF_MAX_S)
            retry = resp.headers.get("Retry-After", "")
            wait = max(self._backoff_s, int(retry) if retry.isdigit() else 0)
            self._backoff_until = self._clock() + min(wait, BACKOFF_MAX_S)
            raise UnifiError("rate_limited", f"HTTP 429; backing off {wait} s")
        self._backoff_s = 0
        if 300 <= resp.status_code < 400:
            raise UnifiError("bad_response", f"HTTP {resp.status_code} redirect not followed")
        return resp

    def close(self):
        self.session.close()


def _json(resp):
    try:
        return resp.json()
    except ValueError:
        raise UnifiError("bad_response", f"HTTP {resp.status_code}: not JSON") from None


class NetworkClient(_Client):
    """UniFi Network legacy API with an API key (``X-API-KEY``)."""

    def __init__(self, url, site, api_key, fingerprint, **kwargs):
        if not api_key:
            raise UnifiError("config", "no Network API key")
        if not re.fullmatch(r"[A-Za-z0-9_-]+", site or ""):
            raise UnifiError("config", "bad Network site name")
        super().__init__(url, fingerprint, **kwargs)
        self.site = site
        self.session.headers["X-API-KEY"] = api_key

    def _legacy(self, method, path, json=None):
        resp = self._request(method, f"/proxy/network/api/s/{self.site}/{path}", json=json)
        if resp.status_code in (401, 403):
            raise UnifiError("auth", f"Network refused the API key (HTTP {resp.status_code})")
        if resp.status_code != 200:
            raise UnifiError("bad_response", f"Network returned HTTP {resp.status_code}")
        data = _json(resp)
        meta = data.get("meta") if isinstance(data, dict) else None
        if not isinstance(meta, dict) or meta.get("rc") != "ok":
            msg = meta.get("msg") if isinstance(meta, dict) else ""
            raise UnifiError("bad_response", f"Network API error {msg or ''}".strip())
        rows = data.get("data")
        if not isinstance(rows, list):
            raise UnifiError("bad_response", "Network returned no data list")
        return [r for r in rows if isinstance(r, dict)]

    def clients(self):
        return self._legacy("GET", "stat/sta")

    def devices(self):
        return self._legacy("GET", "stat/device")

    def power_cycle(self, switch_mac, port_idx):
        _require_live()
        return self._legacy("POST", "cmd/devmgr",
                            {"cmd": "power-cycle", "mac": switch_mac, "port_idx": port_idx})


class ConnectClient(_Client):
    """UniFi Connect through a console web session (no API keys)."""

    def __init__(self, url, username, password, fingerprint, **kwargs):
        if not username or not password:
            raise UnifiError("config", "no Connect username/password")
        super().__init__(url, fingerprint, **kwargs)
        self._username, self._password = username, password
        self._csrf = ""
        self._logged_in = False
        self._logins = []

    def _take_csrf(self, resp):
        token = resp.headers.get("X-Updated-CSRF-Token") or resp.headers.get("X-Csrf-Token")
        if token:
            self._csrf = token

    def _login(self):
        now = self._clock()
        self._logins = [t for t in self._logins if now - t < LOGIN_WINDOW_S]
        if len(self._logins) >= MAX_LOGINS:
            raise UnifiError("auth", "too many Connect logins; waiting before trying again")
        self._logins.append(now)
        resp = self._request("POST", "/api/auth/login",
                             json={"username": self._username, "password": self._password})
        if resp.status_code in (401, 403):
            raise UnifiError("auth", f"Connect login refused (HTTP {resp.status_code})")
        if resp.status_code != 200:
            raise UnifiError("bad_response", f"Connect login returned HTTP {resp.status_code}")
        self._take_csrf(resp)
        self._logged_in = True

    def _call(self, method, path, json=None):
        if not self._logged_in:
            self._login()
        for attempt in range(2):
            headers = {"X-Csrf-Token": self._csrf} if self._csrf else {}
            resp = self._request(method, path, headers=headers, json=json)
            self._take_csrf(resp)
            if resp.status_code == 401 and attempt == 0:
                self._logged_in = False
                self._login()
                continue
            break
        if resp.status_code in (401, 403):
            raise UnifiError("auth", f"Connect refused the session (HTTP {resp.status_code})")
        if resp.status_code == 404 or "client not found" in resp.text[:500].lower():
            raise UnifiError("not_found", "Connect: client not found")
        if resp.status_code != 200:
            raise UnifiError("bad_response", f"Connect returned HTTP {resp.status_code}")
        return _json(resp)

    def devices(self):
        data = self._call("GET", "/proxy/connect/api/v2/devices")
        rows = data.get("data") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            raise UnifiError("bad_response", "Connect returned no device list")
        return [r for r in rows if isinstance(r, dict)]

    def action(self, device_id, action_id, name, args=None):
        _require_live()
        data = self._call("PATCH", f"/proxy/connect/api/v2/devices/{quote(str(device_id), safe='')}/status",
                          {"id": action_id, "name": name, "args": args or {}})
        if not isinstance(data, dict) or data.get("data") != "OK":
            raise UnifiError("bad_response", "Connect did not confirm the action")
        return data


def connect_mac(dev):
    return (dev.get("mac") or dev.get("macAddress") or "").strip().lower().replace("-", ":")


def connect_ip(dev):
    return dev.get("ip") or dev.get("ipAddress") or ""


def connect_online(dev):
    for key in ("online", "isOnline", "connected", "isConnected"):
        if isinstance(dev.get(key), bool):
            return dev[key]
    state = str(dev.get("state") or dev.get("status") or "").lower()
    if state:
        return state in ("online", "connected", "ready", "adopted")
    return None
