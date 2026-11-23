"""Background loop for the watchdog, plus a liveness check that restarts a stuck process."""
import logging
import os
import sys
import threading
import time

log = logging.getLogger(__name__)

TICK_S = 30
DEADLINE_S = 180  # a loop running longer than this means the worker is wedged

_started = False
_start_lock = threading.Lock()
_wake = threading.Event()
_busy_since = None


def _is_runtime(path):
    """``python -m bdh_sdk.runtime`` (the app's container) runs ``bdh_sdk/runtime/__main__.py``."""
    parts = path.replace("\\", "/").split("/")
    return parts[-3:] == ["bdh_sdk", "runtime", "__main__.py"]


def in_container(argv=None):
    argv = sys.argv if argv is None else argv
    return bool(argv) and _is_runtime(argv[0])


def should_start(argv=None):
    """Start only in the server process (the app's container, Daphne, or runserver's reloaded child)."""
    if os.environ.get("BDH_UNIFI_SCREENS_WORKER", "").lower() in ("0", "false", "off", "no"):
        return False
    argv = sys.argv if argv is None else argv
    if in_container(argv):
        return True
    prog = os.path.basename(argv[0]) if argv else ""
    if "daphne" in prog:
        return True
    if len(argv) > 1 and prog in ("manage.py", "django-admin", "__main__.py"):
        if argv[1] == "runserver":
            return os.environ.get("RUN_MAIN") == "true" or "--noreload" in argv
        return False
    return False


def poke():
    _wake.set()


def _run():
    from django.db import close_old_connections

    from . import executor, service

    try:
        executor.recover_after_restart(service._dt(time.time()))
    except Exception:
        log.exception("unifi_screens: settling earlier actions failed")
    dog = service.Watchdog()
    global _busy_since
    while True:
        _busy_since = time.monotonic()
        try:
            close_old_connections()
            dog.tick()
        except Exception:
            log.exception("unifi_screens: loop failed")
        finally:
            _busy_since = None
            close_old_connections()
        _wake.wait(TICK_S)
        _wake.clear()


def overdue(now=None):
    since = _busy_since
    now = time.monotonic() if now is None else now
    return since is not None and now - since > DEADLINE_S


def _liveness(exit=os._exit):
    """Exit the process if a loop hangs, so the supervisor restarts the container."""
    while True:
        time.sleep(15)
        if overdue():
            log.error("unifi_screens: loop stuck for over %s s; exiting for a restart", DEADLINE_S)
            exit(70)


def start():
    global _started
    with _start_lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_run, daemon=True, name="unifi-screens-worker").start()
    # Only in the app's own container: never take the whole hub down in-process.
    if in_container():
        threading.Thread(target=_liveness, daemon=True, name="unifi-screens-liveness").start()
