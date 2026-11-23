"""The single settings page (admins only). No on-screen UI anywhere else, by design."""
import time

from bdh_sdk.auth import is_admin
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.utils import timezone

from . import engine, executor, notify, service, worker
from .interlock import norm_mac
from .models import Action, Decision, Enrollment, Incident, Kv, Pin
from .unifi import UnifiError, origin, pretty_fingerprint

NOTE = "unifi_screens_note"
PAUSES = {"1h": 3600, "4h": 4 * 3600, "resume_only": None}


def _admin(view):
    def wrapped(request, *args, **kwargs):
        if not is_admin(request):
            return HttpResponseForbidden("Admins only")
        return view(request, *args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


def _console():
    try:
        host, port = origin(service.setting("network_url").strip())
    except UnifiError:
        return ""
    return f"{host}:{port}"


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _post(request):
    act = request.POST.get("action", "")
    now = timezone.now()
    if act == "trust":
        pin = Pin.objects.filter(service=request.POST.get("service")).first()
        fp = request.POST.get("fingerprint", "")
        if pin is None or not pin.pending or fp != pin.pending:
            return "bad", "The certificate changed again; check the new fingerprint."
        pin.fingerprint, pin.trusted_at, pin.pending = pin.pending, now, ""
        pin.save()
        service.forget_client(pin.service)
        notify.resolve("pin", pin.service, now=now)
        worker.poke()
        return "ok", f"Trusted the {pin.service} console certificate."
    if act == "forget_pin":
        pin = Pin.objects.filter(service=request.POST.get("service")).first()
        if pin:
            pin.fingerprint, pin.trusted_at = "", None
            pin.save()
            service.forget_client(pin.service)
            worker.poke()
        return "ok", "Pin removed. Trust the certificate again to reconnect."
    if act == "enroll":
        mac = norm_mac(request.POST.get("mac"))
        cand = next((c for c in service.kv_get("candidates", []) if c["mac"] == mac), None)
        if cand is None or not cand.get("switch_mac") or cand.get("switch_port") is None:
            return "bad", "That screen can't be enrolled (not found or not on a switch port)."
        console = _console()
        if not console:
            return "bad", "Set the Network console URL first."
        Enrollment.objects.update_or_create(console=console, mac=mac, defaults={
            "name": cand.get("name", "")[:100], "connect_id": cand.get("connect_id", ""),
            "switch_mac": cand["switch_mac"], "switch_port": cand["switch_port"],
            "ip": cand.get("ip", ""), "topology_hold": False, "state": engine.new_state()})
        worker.poke()
        return "ok", f"Enrolled {cand.get('name') or mac}."
    if act in ("unenroll", "reapprove", "recover"):
        enr = Enrollment.objects.filter(pk=_int(request.POST.get("id"))).first()
        if enr is None:
            return "bad", "No such screen."
        if act == "unenroll":
            enr.delete()
            return "ok", f"Unenrolled {enr}."
        if act == "reapprove":
            if enr.observed_switch_mac and enr.observed_switch_port is not None:
                enr.switch_mac, enr.switch_port = enr.observed_switch_mac, enr.observed_switch_port
            enr.topology_hold = False
            enr.observed_switch_mac, enr.observed_switch_port = "", None
            enr.state = engine.new_state()
            enr.save()
            notify.resolve("topology", enr.mac, now=now)
            return "ok", f"Approved {enr} on {enr.switch_mac} port {enr.switch_port}."
        return _recover(enr, now)
    if act == "pause":
        secs = PAUSES.get(request.POST.get("length"), 3600)
        executor.pause(now, secs)
        return "ok", "Recovery paused" + (" until resumed." if secs is None else f" for {secs // 3600} h.")
    if act == "resume":
        executor.resume()
        worker.poke()
        return "ok", "Recovery resumed."
    if act == "send_test":
        ok, err = notify.send("Screens: test", "Test notification from the screen watchdog.")
        return ("ok", "Test notification sent.") if ok else ("bad", f"Notify failed: {err}")
    if act == "close_incident":
        Incident.objects.filter(pk=_int(request.POST.get("id"))).update(open=False, last_at=now)
        return "ok", "Incident closed."
    return "bad", "Unknown action."


def _recover(enr, now):
    """Manual recovery goes through the same executor (dry run in this version)."""
    conn = enr.last_connect
    connect = {"yes": True, "no": False, "off": "off"}.get(conn, None)
    step = engine.next_step(enr.state or {}, connect)
    if not step:
        return "bad", "No recovery step is available now (gave up, or Connect state unknown)."
    net = con = None
    if step == engine.POE:
        net, _, _ = service.default_network(time.time(), cache=False)
    else:
        con, _, _ = service.default_connect(time.time(), cache=False)
    try:
        out = executor.execute(enr.pk, step, origin="manual", now=now,
                               evidence={"requested_by": "admin"}, network=net, connect=con)
    finally:
        for c in (net, con):
            if c is not None:
                c.close()
    Decision.objects.create(at=now, mac=enr.mac, kind="manual", step=step,
                            reason=f"Recover now: {out.status} ({out.reason})", evidence=out.evidence)
    if out.status == Action.DRY_RUN:
        return "ok", f"Dry run: would {engine.STEP_NAMES[step]} on {enr}."
    return "bad", f"Not done: {out.reason}."


def _pins():
    out = []
    for svc in ("network", "connect"):
        pin = Pin.objects.filter(service=svc).first()
        out.append({
            "service": svc, "host": pin.host if pin else "",
            "trusted": pretty_fingerprint(pin.fingerprint) if pin and pin.fingerprint else "",
            "trusted_at": pin.trusted_at if pin else None,
            "pending_raw": pin.pending if pin else "",
            "pending": pretty_fingerprint(pin.pending) if pin and pin.pending else "",
        })
    return out


def _screens():
    now = timezone.now()
    rows = []
    for enr in Enrollment.objects.all():
        st = enr.state or {}
        rows.append({
            "e": enr, "step": engine.STEP_NAMES.get(st.get("step") or 0, "-"),
            "state": "gave up" if st.get("gave_up") else ("bad" if st.get("bad_since") else
                                                         ("healthy" if st.get("healthy_since") else "watching")),
            "dry_runs": Action.objects.filter(enrollment=enr, mode="dry_run", status=Action.DRY_RUN).count(),
            "dry_poe_24h": executor.poe_used(enr.mac, "dry_run", now),
        })
    return rows


@_admin
def settings_page(request):
    if request.method == "POST":
        request.session[NOTE] = _post(request)
        return redirect("unifi_screens_settings")
    active, until = executor.pause_state(timezone.now())
    status = Kv.objects.filter(key="status").first()
    return render(request, "unifi_screens/settings.html", {
        "note": request.session.pop(NOTE, None),
        "status": status.value if status else {},
        "status_at": status.updated_at if status else None,
        "pins": _pins(),
        "screens": _screens(),
        "candidates": service.kv_get("candidates", []),
        "paused": active, "paused_until": until,
        "incidents": Incident.objects.all()[:30],
        "decisions": Decision.objects.all()[:60],
        "actions": Action.objects.all()[:30],
        "notify_target": notify.notify_target(),
        "live": executor.LIVE_ACTIONS_ALLOWED,
    })
