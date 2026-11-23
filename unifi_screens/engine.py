"""The decision engine: pure functions over plain dicts and an injected clock.

Each loop the worker builds one :class:`Obs` per enrolled screen and calls
:func:`decide`. The engine returns the screens' new states plus a list of
:class:`Verdict` (hold / act / recovered / gave_up / breaker). It never talks
to anything; acting is the executor's job, and the worker reports back with
:func:`record_attempt` whether the step was dispatched (or, in dry run,
recorded) so the observe window starts.

Times are epoch seconds (floats).
"""
from dataclasses import dataclass, field

STALE_S = 300  # H: heartbeat older than this = screen quiet
OUTAGE_GRACE_S = 300  # after any dependency outage, watch this long before acting
GRACE_S = 120  # bad this long before step 1
HEALTHY_RESET_S = 600  # continuously healthy this long resets the escalation
MAX_POE_CYCLES = 3  # PoE cycles without recovery before giving up

RESTORE, REBOOT, POE = 1, 2, 3
STEP_NAMES = {RESTORE: "restore kiosk", REBOOT: "Connect reboot", POE: "PoE power-cycle"}
OBSERVE_S = {RESTORE: 120, REBOOT: 240, POE: 240}

HEALTHY, BAD, UNKNOWN = "healthy", "bad", "unknown"


@dataclass
class Obs:
    """What the worker saw for one enrolled screen this loop.

    ``h``/``l``: True, False or None (unknown). ``connect``: True when the
    screen is reachable in Connect, False when Connect is configured but the
    device is offline/missing there, None when Connect is down/unknown, and
    "off" when no Connect console is configured.
    """

    mac: str
    h: object = None
    l: object = None
    connect: object = "off"
    held: str = ""  # non-empty: recovery held for this reason (topology change...)
    evidence: dict = field(default_factory=dict)


@dataclass
class Verdict:
    mac: str
    kind: str  # hold / act / recovered / gave_up / breaker / reset
    step: int = 0
    reason: str = ""
    evidence: dict = field(default_factory=dict)


def health(obs):
    if obs.h is True:
        return HEALTHY
    if obs.h is False and obs.l is not None:
        return BAD
    return UNKNOWN


def new_state():
    return {"step": 0, "poe_cycles": 0, "gave_up": False, "bad_since": None,
            "healthy_since": None, "grace_until": None, "observe_until": None}


def next_step(state, connect):
    """The ladder step after ``state['step']``, skipping steps whose precondition fails.

    Returns 0 when nothing may be tried now.
    """
    if state.get("gave_up"):
        return 0
    if (state.get("step") or 0) >= POE and (state.get("poe_cycles") or 0) >= MAX_POE_CYCLES:
        return 0
    step = state.get("step") or 0
    for candidate in range(step + 1, POE + 1):
        if candidate in (RESTORE, REBOOT):
            if connect is True:
                return candidate
            if connect is None:  # Connect configured but unknown: don't skip past it
                return 0
            continue
        return candidate
    return POE  # after a PoE cycle, the next try is another PoE cycle


def _connect_reason(connect):
    return "Connect unavailable" if connect is None else ""


def decide(now, screens, *, paused=False, site_unknown=""):
    """One loop. ``screens`` is a list of ``(state, Obs)``.

    Returns ``(new_states, verdicts)``; ``new_states`` is in the same order.
    ``site_unknown`` (e.g. "broker unreachable") makes every screen unknown.
    """
    states = [dict(new_state(), **(s or {})) for s, _ in screens]
    obs_list = [o for _, o in screens]
    verdicts = []
    status = []

    for st, obs in zip(states, obs_list):
        hs = UNKNOWN if site_unknown else health(obs)
        status.append(hs)
        if hs == UNKNOWN:
            st["grace_until"] = now + OUTAGE_GRACE_S
            st["bad_since"] = None
            st["healthy_since"] = None
            continue
        if hs == HEALTHY:
            if st["bad_since"] is not None and st["step"] >= REBOOT:
                verdicts.append(Verdict(obs.mac, "recovered", st["step"],
                                        f"healthy again after {STEP_NAMES[st['step']]}"))
            st["bad_since"] = None
            if st["healthy_since"] is None:
                st["healthy_since"] = now
            if (st["step"] or st["gave_up"]) and now - st["healthy_since"] >= HEALTHY_RESET_S:
                verdicts.append(Verdict(obs.mac, "reset", 0,
                                        f"healthy for {HEALTHY_RESET_S} s: escalation reset"))
                st.update(step=0, poe_cycles=0, gave_up=False, observe_until=None)
        else:
            st["healthy_since"] = None
            if st["bad_since"] is None:
                st["bad_since"] = now

    # Site circuit breaker: several screens lose H at once while the network
    # still sees them -> the hub/ingress is the likely problem, not the screens.
    enrolled = len(screens)
    quiet_but_linked = [o.mac for o, hs in zip(obs_list, status) if hs == BAD and o.l is True]
    threshold = min(2, enrolled)
    if enrolled and len(quiet_but_linked) >= threshold:
        verdicts.append(Verdict("", "breaker", 0,
                                f"{len(quiet_but_linked)} of {enrolled} screens quiet while connected",
                                {"screens": quiet_but_linked}))
        for st, obs, hs in zip(states, obs_list, status):
            if hs == BAD:
                verdicts.append(Verdict(obs.mac, "hold", 0, "site circuit breaker"))
        return states, verdicts

    busy = any(st["observe_until"] and now < st["observe_until"] and hs == BAD
               for st, hs in zip(states, status))
    candidates = []
    for st, obs, hs in zip(states, obs_list, status):
        if hs != BAD:
            if hs == UNKNOWN:
                verdicts.append(Verdict(obs.mac, "hold", 0, "unknown: never acts"))
            continue
        reason = _hold_reason(now, st, obs, paused)
        if reason:
            verdicts.append(Verdict(obs.mac, "hold", 0, reason))
            continue
        if st["step"] >= POE and st["poe_cycles"] >= MAX_POE_CYCLES:
            st["gave_up"] = True
            verdicts.append(Verdict(obs.mac, "gave_up", POE,
                                    f"{MAX_POE_CYCLES} PoE cycles without recovery"))
            continue
        step = next_step(st, obs.connect)
        if not step:
            verdicts.append(Verdict(obs.mac, "hold", 0,
                                    _connect_reason(obs.connect) or "no step available"))
            continue
        candidates.append((st["bad_since"], obs.mac, step))

    # Serialized: one recovery at a time, oldest failure first.
    candidates.sort()
    for i, (_, mac, step) in enumerate(candidates):
        if busy or i > 0:
            verdicts.append(Verdict(mac, "hold", step, "another recovery in progress"))
        else:
            verdicts.append(Verdict(mac, "act", step, f"step {step}: {STEP_NAMES[step]}"))
    return states, verdicts


def _hold_reason(now, st, obs, paused):
    if obs.held:
        return obs.held
    if st["gave_up"]:
        return "gave up: waiting for the screen to be healthy"
    if st["grace_until"] and now < st["grace_until"]:
        return "observing after a dependency outage"
    if st["step"] == 0 and now - st["bad_since"] < GRACE_S:
        return "grace before the first step"
    if st["observe_until"] and now < st["observe_until"]:
        return "observing the last step"
    if paused:
        return "paused"
    return ""


def record_attempt(state, step, now, dispatched):
    """Start the observe window after the executor ran (or refused) ``step``.

    A refused step still waits one window before it is tried again, so a
    refusal is recorded once per window, not every loop.
    """
    st = dict(new_state(), **(state or {}))
    st["observe_until"] = now + OBSERVE_S[step]
    if dispatched:
        st["step"] = step
        if step == POE:
            st["poe_cycles"] = (st.get("poe_cycles") or 0) + 1
    return st
