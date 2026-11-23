"""Incidents: persisted, deduplicated, delivered by phone notify and an admins-only alert."""
import logging
from datetime import timedelta

from bdh_sdk import alerts, ha
from bdh_sdk.settings import app_setting
from django.utils import timezone

from .models import Incident

log = logging.getLogger(__name__)

APP = "unifi_screens"
SETTINGS_PATH = "/unifi-screens/settings/"
RENOTIFY = timedelta(hours=12)  # an incident that keeps recurring is re-sent at most this often


def notify_target():
    """``(domain, service)`` from the ``notify_service`` setting, or None."""
    raw = (app_setting(APP, "notify_service", "") or "").strip()
    if not raw:
        return None
    domain, _, service = raw.partition(".")
    if not service:
        domain, service = "notify", domain
    if domain != "notify" or not service.replace("_", "").isalnum():
        return None
    return domain, service


def send(title, message):
    """Deliver one phone notification. Returns ``(ok, error)``."""
    target = notify_target()
    if target is None:
        return False, "no notify service configured"
    try:
        return ha.call_service(target[0], target[1], None, {"title": title, "message": message})
    except Exception as exc:  # noqa: BLE001 - broker errors etc.
        return False, str(exc)


def _alert(inc):
    try:
        alerts.push(alerts.Alert(app=APP, key=f"incident:{inc.pk}", title=inc.title[:120],
                                 body=inc.message[:200], embed_url=SETTINGS_PATH, ttl=300,
                                 wake=False, admins_only=True))
    except Exception:  # noqa: BLE001
        log.exception("unifi_screens: alert push failed")


def raise_incident(kind, key, title, message="", mac="", now=None):
    """Open (or bump) the incident ``(kind, key)``; notify on open and every RENOTIFY."""
    now = now or timezone.now()
    inc = Incident.objects.filter(kind=kind, key=key, open=True).first()
    if inc is None:
        inc = Incident.objects.create(kind=kind, key=key, mac=mac, title=title[:200],
                                      message=message, first_at=now, last_at=now)
    else:
        inc.count += 1
        inc.last_at = now
        inc.message = message or inc.message
        inc.save(update_fields=["count", "last_at", "message"])
    if inc.notified_at is None or now - inc.notified_at >= RENOTIFY:
        ok, err = send(f"Screens: {inc.title}", inc.message or inc.title)
        inc.notified_at = now
        inc.notify_error = "" if ok else (err or "failed")[:300]
        inc.save(update_fields=["notified_at", "notify_error"])
        _alert(inc)
    return inc


def resolve(kind, key, now=None):
    now = now or timezone.now()
    for inc in Incident.objects.filter(kind=kind, key=key, open=True):
        inc.open = False
        inc.last_at = now
        inc.save(update_fields=["open", "last_at"])
        try:
            alerts.dismiss(APP, f"incident:{inc.pk}")
        except Exception:  # noqa: BLE001
            pass
