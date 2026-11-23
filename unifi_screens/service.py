"""One watchdog loop: read the dependencies, observe, decide, (dry-run) act, report.

Everything external is injected so tests can drive a loop with fakes and a
fake clock. The settings page reads only what this writes to the database.
"""
import hashlib
import logging
import time
from datetime import datetime, timezone as dt_tz

from bdh_sdk import secrets
from bdh_sdk.settings import app_setting, as_bool

from . import engine, executor, notify
from .discovery import candidates
from .interlock import norm_mac, port_entry
from .models import Decision, Enrollment, Kv, Pin
from .unifi import (ConnectClient, NetworkClient, UnifiError, connect_mac, connect_online,
                    fetch_fingerprint, origin)

log = logging.getLogger(__name__)

APP = "unifi_screens"
DECISIONS_KEPT = 500


def _dt(ts):
    return datetime.fromtimestamp(ts, tz=dt_tz.utc)


def setting(key, default=""):
    return (app_setting(APP, key, default) or default)


def secret(name):
    return secrets.get(name, "", app=APP) or ""


def kv_get(key, default=None):
    row = Kv.objects.filter(key=key).first()
    return row.value if row else default


def kv_set(key, value):
    Kv.objects.update_or_create(key=key, defaults={"value": value})


# ---- dependencies -------------------------------------------------------------

def read_displays(fetch=None):
    """``(state, detail, heartbeats{ip: age_s}, ready_age_s)``.

    state: ok / unavailable (H unknown) / denied / unsupported (recovery disabled).
    Never falls back to the hub's open heartbeat endpoint.
    """
    from bdh_sdk import displays
    from bdh_sdk.rpc import BrokerError, PermissionDenied

    try:
        raw = (fetch or displays.status)()
    except PermissionDenied as exc:
        return "denied", f"displays.read not granted ({exc})", {}, None
    except BrokerError as exc:
        if exc.code in ("not_found", "not_installed", "unknown_op"):
            return "unsupported", f"this hub has no displays.status ({exc.code})", {}, None
        return "unavailable", f"broker: {exc}", {}, None
    except Exception as exc:  # noqa: BLE001
        return "unavailable", f"displays.status failed: {exc}", {}, None
    beats = {}
    for c in raw.get("clients") or ():
        if c.get("ip") and isinstance(c.get("age_seconds"), (int, float)):
            beats[c["ip"]] = c["age_seconds"]
    ready, now = raw.get("ready_since"), raw.get("now")
    ready_age = (now - ready).total_seconds() if ready and now else None
    return "ok", "", beats, ready_age


_clients = {}


def pinned_client(service, url, build, now, creds="", cache=True):
    """``(client or None, state, detail)``. Handles TOFU: an unknown cert is only *pending*.

    Clients (and their sessions) are reused while URL, pin and credentials stay the same.
    """
    try:
        host, port = origin(url)
    except UnifiError as exc:
        return None, "config", str(exc)
    where = f"{host}:{port}"
    pin = Pin.objects.filter(service=service).first() or Pin(service=service)
    if pin.host != where:
        pin.host, pin.fingerprint, pin.trusted_at, pin.pending = where, "", None, ""
    if not pin.fingerprint:
        _clients.pop(service, None)
        try:
            pin.pending = fetch_fingerprint(url)
            pin.pending_at = _dt(now)
        except UnifiError as exc:
            pin.save()
            return None, exc.kind, str(exc)
        pin.save()
        return None, "pin_required", "certificate not trusted yet: check the fingerprint and click Trust"
    if pin.pk is None:
        pin.save()
    key = (url, pin.fingerprint, hashlib.sha256(creds.encode()).hexdigest())
    if not cache:
        try:
            return build(pin.fingerprint), "ok", ""
        except UnifiError as exc:
            return None, exc.kind, str(exc)
    cached = _clients.get(service)
    if cached and cached[0] == key:
        return cached[1], "ok", ""
    try:
        client = build(pin.fingerprint)
    except UnifiError as exc:
        return None, exc.kind, str(exc)
    if cached:
        cached[1].close()
    _clients[service] = (key, client)
    return client, "ok", ""


def forget_client(service):
    cached = _clients.pop(service, None)
    if cached:
        cached[1].close()



def pin_mismatch(service, url, now):
    """Record the certificate now presented as pending re-pin (sends no credentials)."""
    pin = Pin.objects.filter(service=service).first()
    if pin is None:
        return
    try:
        pin.pending = fetch_fingerprint(url)
        pin.pending_at = _dt(now)
        pin.save(update_fields=["pending", "pending_at"])
    except UnifiError:
        pass


def default_network(now, cache=True):
    url = setting("network_url").strip()
    if not url:
        return None, "off", "not configured"
    key, site = secret("network_api_key"), setting("network_site", "default").strip() or "default"
    return pinned_client("network", url, lambda fp: NetworkClient(url, site, key, fp), now,
                         creds=f"{site}\0{key}", cache=cache)


def default_connect(now, cache=True):
    url = setting("connect_url").strip()
    if not url:
        return None, "off", "not configured"
    user, pw = setting("connect_username").strip(), secret("connect_password")
    return pinned_client("connect", url, lambda fp: ConnectClient(url, user, pw, fp), now,
                         creds=f"{user}\0{pw}", cache=cache)


# ---- observation ----------------------------------------------------------------

def observe(enr, *, h_state, beats, ready_age, net, connect_state, connect_devs):
    """Build the engine's :class:`~.engine.Obs` for one enrollment.

    ``net`` is ``(clients, devices)`` or None when the Network console is unknown.
    Returns ``(obs, updates)``; ``updates`` are Enrollment fields to save.
    """
    mac = norm_mac(enr.mac)
    ev = {"ip": None}
    updates = {}
    ip = enr.ip or None
    l = None
    client = None
    if net is not None:
        clients, devices = net
        client = next((c for c in clients if norm_mac(c.get("mac")) == mac), None)
        if client is not None:
            ip = client.get("ip") or None
            sw, port_idx = norm_mac(client.get("sw_mac")), client.get("sw_port")
            ev.update(sw_mac=sw, sw_port=port_idx)
            dev = next((d for d in devices if norm_mac(d.get("mac")) == sw), None)
            port = port_entry(dev, port_idx) if dev else None
            ev["port_up"] = port.get("up") if port else None
            l = bool(port and port.get("up"))
            if (sw, port_idx) != (norm_mac(enr.switch_mac), enr.switch_port) and sw:
                updates.update(topology_hold=True, observed_switch_mac=sw,
                               observed_switch_port=port_idx)
        else:
            l = False
            ev["client"] = "missing from Network"
            # Don't trust the last-known IP if another device holds it now (DHCP reuse).
            if ip and any(c.get("ip") == ip for c in clients):
                ev["ip_reused_by"] = next(norm_mac(c.get("mac")) for c in clients if c.get("ip") == ip)
                ip = None
        if ip and ip != enr.ip and client is not None:
            updates["ip"] = ip
    ev["ip"] = ip

    if h_state != "ok" or ready_age is None or ready_age < engine.STALE_S:
        h = None
        ev["h"] = "unknown: broker unavailable" if h_state != "ok" else "unknown: hub just started"
    elif ip is None:
        h = False
    else:
        age = beats.get(ip)
        ev["heartbeat_age"] = age
        h = age is not None and age < engine.STALE_S

    if connect_state == "off":
        conn = "off"
    elif connect_devs is None:
        conn = None
    else:
        dev = next((d for d in connect_devs if (enr.connect_id and str(d.get("id")) == enr.connect_id)
                    or connect_mac(d) == mac), None)
        conn = False if dev is None else connect_online(dev) is not False
        ev["connect"] = "missing" if dev is None else ("online" if conn else "offline")

    held = "topology changed: needs re-approval" if (enr.topology_hold or updates.get("topology_hold")) else ""
    return engine.Obs(mac=mac, h=h, l=l, connect=conn, held=held, evidence=ev), updates


def _tri(v):
    return {True: "yes", False: "no", None: "?", "off": "off"}.get(v, str(v))


# ---- the loop ---------------------------------------------------------------------

class Watchdog:
    def __init__(self, *, clock=time.time, displays=None, network=None, connect=None):
        self.clock = clock
        self._displays = displays
        self._network = network or default_network
        self._connect = connect or default_connect

    def tick(self):
        now = self.clock()
        nowdt = _dt(now)
        status = {"last_loop": nowdt.isoformat(), "enabled": False}
        if not as_bool(app_setting(APP, "enabled", False)):
            status["disabled_reason"] = "turned off in the app settings"
            kv_set("status", {**kv_get("status", {}), **status})
            return status
        status["enabled"] = True

        h_state, h_detail, beats, ready_age = read_displays(self._displays)
        status["displays"] = {"state": h_state, "detail": h_detail}
        if h_state in ("denied", "unsupported"):
            status["disabled_reason"] = f"recovery disabled: {h_detail}"
            notify.raise_incident("displays", h_state, "Screen recovery is disabled", h_detail, now=nowdt)
        else:
            notify.resolve("displays", "denied", now=nowdt)
            notify.resolve("displays", "unsupported", now=nowdt)

        net_client, n_state, n_detail = self._network(now)
        net = None
        if net_client is not None:
            try:
                net = (net_client.clients(), net_client.devices())
            except UnifiError as exc:
                n_state, n_detail = exc.kind, str(exc)
                net_client = None
                if exc.kind == "pin":
                    pin_mismatch("network", setting("network_url").strip(), now)
        status["network"] = {"state": n_state, "detail": n_detail}

        con_client, c_state, c_detail = self._connect(now)
        cdevs = None
        if con_client is not None:
            try:
                cdevs = con_client.devices()
            except UnifiError as exc:
                c_state, c_detail = exc.kind, str(exc)
                con_client = None
                if exc.kind == "pin":
                    pin_mismatch("connect", setting("connect_url").strip(), now)
        status["connect"] = {"state": c_state, "detail": c_detail}

        for svc, st, detail in (("network", n_state, n_detail), ("connect", c_state, c_detail)):
            for kind in ("pin", "auth"):
                if st == kind:
                    notify.raise_incident(kind, svc, f"UniFi {svc.title()}: "
                                          + ("certificate changed" if kind == "pin" else "login refused"),
                                          detail, now=nowdt)
                else:
                    notify.resolve(kind, svc, now=nowdt)

        enrollments = list(Enrollment.objects.all())
        if net is not None and h_state == "ok":
            kv_set("candidates", candidates(beats, net[0], cdevs or [], [e.mac for e in enrollments]))

        if h_state not in ("denied", "unsupported"):
            self._run_engine(now, nowdt, enrollments, h_state, beats, ready_age, net, c_state, cdevs,
                             net_client, con_client)
        status["last_ok"] = nowdt.isoformat()
        kv_set("status", status)
        return status

    def _run_engine(self, now, nowdt, enrollments, h_state, beats, ready_age, net, c_state, cdevs,
                    net_client, con_client):
        pairs, upd = [], []
        for enr in enrollments:
            obs, updates = observe(enr, h_state=h_state, beats=beats, ready_age=ready_age, net=net,
                                   connect_state=c_state, connect_devs=cdevs)
            if updates.get("topology_hold") and not enr.topology_hold:
                notify.raise_incident(
                    "topology", enr.mac, f"{enr} moved to another switch port",
                    f"Expected {enr.switch_mac} port {enr.switch_port}, now on "
                    f"{updates['observed_switch_mac']} port {updates['observed_switch_port']}. "
                    "Recovery is held until an admin re-approves it.", mac=enr.mac, now=nowdt)
            for k, v in updates.items():
                setattr(enr, k, v)
            pairs.append((enr.state, obs))
            upd.append(enr)
        paused = executor.pause_state(nowdt)[0]
        site_unknown = "broker unavailable" if h_state != "ok" else ""
        states, verdicts = engine.decide(now, pairs, paused=paused, site_unknown=site_unknown)
        by_mac = {}
        for enr, st, (_, obs) in zip(upd, states, pairs):
            enr.state = st
            enr.last_h, enr.last_l, enr.last_connect = _tri(obs.h), _tri(obs.l), _tri(obs.connect)
            by_mac[obs.mac] = (enr, obs)

        for v in verdicts:
            self._handle(v, by_mac, now, nowdt, net_client, con_client)
        for enr in upd:
            enr.save()
        old = Decision.objects.order_by("-at", "-id").values_list("id", flat=True)[DECISIONS_KEPT:]
        Decision.objects.filter(id__in=list(old)).delete()

    def _record(self, nowdt, v, enr=None, text=None, evidence=None):
        text = text or v.reason
        ev = {**(v.evidence or {}), **(evidence or {})}
        if enr is not None:
            if enr.last_decision == text and v.kind == "hold":
                return  # unchanged hold: don't flood the history
            enr.last_decision, enr.last_decision_at = text[:300], nowdt
        Decision.objects.create(at=nowdt, mac=v.mac, kind=v.kind, step=v.step or None,
                                reason=text[:300], evidence=ev)

    def _handle(self, v, by_mac, now, nowdt, net_client, con_client):
        enr, obs = by_mac.get(v.mac, (None, None))
        ev = dict(obs.evidence) if obs else {}
        if v.kind == "breaker":
            self._record(nowdt, v)
            notify.raise_incident("breaker", "site", "Several screens went quiet at once",
                                  f"{v.reason}. Likely a hub or network problem; no screen was touched.",
                                  now=nowdt)
            return
        if v.kind == "act":
            out = executor.execute(enr.pk, v.step, origin="auto", now=nowdt, evidence=ev,
                                   network=net_client, connect=con_client)
            enr.state = engine.record_attempt(enr.state, v.step, now, out.dispatched)
            verb = "Would " if out.status == "dry_run" else ""
            text = (f"{verb}{engine.STEP_NAMES[v.step]} (dry run)" if out.status == "dry_run"
                    else f"{engine.STEP_NAMES[v.step]}: {out.status} ({out.reason})")
            self._record(nowdt, v, enr, text, {"action": out.action_id, **out.evidence})
            return
        if v.kind == "gave_up":
            notify.raise_incident("gave_up", enr.mac, f"{enr} did not recover",
                                  f"{v.reason} (dry run: nothing was actually done).", mac=enr.mac, now=nowdt)
        elif v.kind in ("recovered", "reset"):
            notify.resolve("gave_up", enr.mac, now=nowdt)
        if enr is not None:
            self._record(nowdt, v, enr, evidence=ev)
