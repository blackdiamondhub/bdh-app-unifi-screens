"""The single, serialized executor for (would-be) destructive recovery actions.

Contract (design §9): reserve an :class:`~.models.Action` row first, then
re-check pause, enrollment, caps/budget and the PoE interlock, then dispatch.
In 0.1.0b1 dispatch only records a dry-run decision: ``LIVE_ACTIONS_ALLOWED``
is False and the executor refuses any live dispatch while it is.
"""
import threading
from dataclasses import dataclass, field
from datetime import timedelta

from . import engine, interlock
from .models import Action, Enrollment, Pause

LIVE_ACTIONS_ALLOWED = False

MAX_POE_PER_DAY = 6
DAY = timedelta(hours=24)
# Statuses that used up the observe window / budget.
COUNTED = (Action.DRY_RUN, Action.DONE, Action.DISPATCHING, Action.POSSIBLY_EXECUTED)

_lock = threading.RLock()


@dataclass
class Outcome:
    status: str
    reason: str = ""
    action_id: int = None
    evidence: dict = field(default_factory=dict)

    @property
    def dispatched(self):
        return self.status in COUNTED


def _finish(action, status, reason, now, **evidence):
    action.status = status
    action.reason = reason[:300]
    action.updated_at = now
    if evidence:
        action.evidence = {**action.evidence, **evidence}
    action.save(update_fields=["status", "reason", "updated_at", "evidence"])
    return Outcome(status, reason, action.pk, action.evidence)


def pause_state(now):
    """``(active, until)``; an expired timed pause switches itself off."""
    p = Pause.objects.filter(pk=1).first()
    if p is None or not p.active:
        return False, None
    if p.until is not None and p.until <= now:
        p.active = False
        p.save(update_fields=["active"])
        return False, None
    return True, p.until


def pause(now, seconds=None):
    """Pause recovery (``seconds`` None: until resumed).

    Returns once queued reservations are cancelled; the count is of actions
    that were already dispatched (and so can't be taken back).
    """
    with _lock:
        Action.objects.filter(status=Action.RESERVED).update(
            status=Action.CANCELLED, reason="paused", updated_at=now)
        Pause.objects.update_or_create(pk=1, defaults={
            "active": True, "since": now,
            "until": now + timedelta(seconds=seconds) if seconds else None})
        return Action.objects.filter(status=Action.DISPATCHING).count()


def resume():
    with _lock:
        Pause.objects.update_or_create(pk=1, defaults={"active": False, "until": None})


def recover_after_restart(now):
    """Settle actions a previous process left half-done. Never retried blindly."""
    with _lock:
        abandoned = Action.objects.filter(status=Action.RESERVED).update(
            status=Action.ABANDONED, reason="restarted before dispatch", updated_at=now)
        unsure = Action.objects.filter(status=Action.DISPATCHING).update(
            status=Action.POSSIBLY_EXECUTED, reason="restarted during dispatch", updated_at=now)
    return abandoned, unsure


def poe_used(mac, mode, now):
    return Action.objects.filter(mac=mac, mode=mode, step=engine.POE, status__in=COUNTED,
                                 created_at__gt=now - DAY).count()


def _in_window(enr, mode, now, exclude):
    for act in (Action.objects.filter(enrollment=enr, mode=mode, status__in=COUNTED)
                .exclude(pk=exclude).order_by("-created_at")[:5]):
        if act.created_at + timedelta(seconds=engine.OBSERVE_S.get(act.step, 240)) > now:
            return act
    return None


def _recheck(action, enrollment_id, step, now, network, connect):
    """Why the reserved action must not go ahead, or "" (fills interlock evidence)."""
    if pause_state(now)[0]:
        return Action.CANCELLED, "paused"
    action.refresh_from_db(fields=["status"])
    if action.status != Action.RESERVED:
        return Action.CANCELLED, "cancelled while queued"
    enr = Enrollment.objects.filter(pk=enrollment_id).first()
    if enr is None:
        return Action.CANCELLED, "no longer enrolled"
    if enr.topology_hold:
        return Action.CANCELLED, "topology changed: needs re-approval"
    earlier = _in_window(enr, action.mode, now, action.pk)
    if earlier is not None:
        return Action.REFUSED, f"cap: action #{earlier.pk} is still in its observe window"
    if step in (engine.RESTORE, engine.REBOOT):
        if connect is None or not enr.connect_id:
            return Action.REFUSED, "Connect not configured for this screen"
        return None, ""
    used = poe_used(enr.mac, action.mode, now)
    action.evidence["poe_used_24h"] = used
    if used >= MAX_POE_PER_DAY:
        return Action.REFUSED, f"budget: {used} PoE cycles in 24 h"
    if network is None:
        return Action.REFUSED, "interlock: Network console unavailable"
    try:
        clients, devices = network.clients(), network.devices()
    except Exception as exc:  # noqa: BLE001 - any read failure refuses
        return Action.REFUSED, f"interlock: fresh read failed ({exc})"
    ok, why, ev = interlock.check(screen_mac=enr.mac, switch_mac=enr.switch_mac,
                                  switch_port=enr.switch_port, clients=clients,
                                  devices=devices, now=now.timestamp())
    action.evidence["interlock"] = {"ok": ok, "reason": why, **ev}
    if not ok:
        return Action.REFUSED, f"interlock: {why}"
    return None, ""


def execute(enrollment_id, step, *, origin, now, evidence=None, network=None, connect=None,
            live=None, _after_reserve=None):
    """Run one ladder ``step`` for an enrolled screen through the full contract."""
    live = LIVE_ACTIONS_ALLOWED if live is None else live
    mode = "live" if live else "dry_run"
    with _lock:
        enr = Enrollment.objects.filter(pk=enrollment_id).first()
        if enr is None:
            return Outcome(Action.REFUSED, "not enrolled")
        action = Action.objects.create(
            enrollment=enr, mac=enr.mac, step=step, origin=origin, mode=mode,
            status=Action.RESERVED, evidence=dict(evidence or {}), created_at=now, updated_at=now)
        if _after_reserve:
            _after_reserve(action)
        status, why = _recheck(action, enrollment_id, step, now, network, connect)
        if status:
            return _finish(action, status, why, now)
        if mode == "dry_run":
            return _finish(action, Action.DRY_RUN, f"would {engine.STEP_NAMES[step]}", now)
        if not LIVE_ACTIONS_ALLOWED:
            return _finish(action, Action.REFUSED, "live actions are disabled in this version", now)
        action.status = Action.DISPATCHING
        action.save(update_fields=["status"])
        return _dispatch_live(action, enr, step, now, network, connect)


def _dispatch_live(action, enr, step, now, network, connect):
    from .unifi import UnifiError

    if not LIVE_ACTIONS_ALLOWED:
        return _finish(action, Action.REFUSED, "live actions are disabled in this version", now)
    try:
        if step == engine.POE:
            network.power_cycle(enr.switch_mac, enr.switch_port)
        else:
            # Restore-kiosk / reboot action ids come from the device's supported
            # actions; the mapping lands with live mode (0.1.0b2).
            raise UnifiError("config", f"{engine.STEP_NAMES[step]} is not mapped yet")
    except UnifiError as exc:
        if exc.kind == "unreachable":
            return _finish(action, Action.POSSIBLY_EXECUTED, f"timeout: {exc}", now)
        return _finish(action, Action.FAILED, str(exc), now)
    return _finish(action, Action.DONE, f"did {engine.STEP_NAMES[step]}", now)
