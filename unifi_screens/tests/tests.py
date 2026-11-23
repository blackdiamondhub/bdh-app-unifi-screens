import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone as dt_tz
from unittest import mock, skipUnless

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from unifi_screens import engine, executor, interlock, service
from unifi_screens.engine import POE, REBOOT, RESTORE, Obs
from unifi_screens.models import Action, Enrollment, Incident
from unifi_screens.unifi import LiveActionsDisabled, NetworkClient, UnifiError, fetch_fingerprint

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover
    x509 = None

SW = "aa:aa:aa:aa:aa:01"
A, B, C = "bb:bb:bb:bb:bb:01", "bb:bb:bb:bb:bb:02", "bb:bb:bb:bb:bb:03"
T0 = 1_700_000_000.0


def _dt(ts):
    return datetime.fromtimestamp(ts, tz=dt_tz.utc)


def obs(mac, h=False, l=True, connect="off", held=""):
    return Obs(mac=mac, h=h, l=l, connect=connect, held=held)


class Sim:
    """Drives the engine like the worker does (recording each act as dispatched)."""

    def __init__(self, *macs):
        self.states = {m: engine.new_state() for m in macs}

    def step(self, now, observations, paused=False, site_unknown=""):
        pairs = [(self.states[o.mac], o) for o in observations]
        states, verdicts = engine.decide(now, pairs, paused=paused, site_unknown=site_unknown)
        for (_, o), st in zip(pairs, states):
            self.states[o.mac] = st
        for v in verdicts:
            if v.kind == "act":
                self.states[v.mac] = engine.record_attempt(self.states[v.mac], v.step, now, True)
        return verdicts


def acts(verdicts):
    return [(v.mac, v.step) for v in verdicts if v.kind == "act"]


def kinds(verdicts, mac):
    return [v.kind for v in verdicts if v.mac == mac]


class EngineTests(SimpleTestCase):
    def test_grace_before_first_step(self):
        sim = Sim(A, B)
        self.assertEqual(acts(sim.step(T0, [obs(A, connect=True), obs(B, h=True)])), [])
        self.assertEqual(acts(sim.step(T0 + 119, [obs(A, connect=True), obs(B, h=True)])), [])
        self.assertEqual(acts(sim.step(T0 + 120, [obs(A, connect=True), obs(B, h=True)])), [(A, RESTORE)])

    def test_escalation_ladder_then_gives_up(self):
        sim = Sim(A, B)
        seen, t = [], T0
        sim.step(t, [obs(A, connect=True), obs(B, h=True)])
        for _ in range(200):
            t += 10
            v = sim.step(t, [obs(A, connect=True), obs(B, h=True)])
            seen += [s for _, s in acts(v)]
            if "gave_up" in kinds(v, A):
                break
        self.assertEqual(seen, [RESTORE, REBOOT, POE, POE, POE])
        self.assertTrue(sim.states[A]["gave_up"])
        # Gave up: nothing more is tried while the screen stays bad.
        self.assertEqual(acts(sim.step(t + 1000, [obs(A, connect=True), obs(B, h=True)])), [])

    def test_steps_wait_for_their_observe_window(self):
        sim = Sim(A, B)
        sim.step(T0, [obs(A, connect=True), obs(B, h=True)])
        sim.step(T0 + 120, [obs(A, connect=True), obs(B, h=True)])  # step 1
        self.assertEqual(acts(sim.step(T0 + 239, [obs(A, connect=True), obs(B, h=True)])), [])
        self.assertEqual(acts(sim.step(T0 + 240, [obs(A, connect=True), obs(B, h=True)])), [(A, REBOOT)])

    def test_connect_steps_skipped_without_connect(self):
        sim = Sim(A, B)
        sim.step(T0, [obs(A), obs(B, h=True)])
        self.assertEqual(acts(sim.step(T0 + 120, [obs(A), obs(B, h=True)])), [(A, POE)])

    def test_escalation_resets_after_600s_healthy(self):
        sim = Sim(A, B)
        sim.step(T0, [obs(A, connect=True), obs(B, h=True)])
        sim.step(T0 + 120, [obs(A, connect=True), obs(B, h=True)])
        sim.step(T0 + 240, [obs(A, connect=True), obs(B, h=True)])
        self.assertEqual(sim.states[A]["step"], REBOOT)
        sim.step(T0 + 300, [obs(A, h=True), obs(B, h=True)])
        sim.step(T0 + 899, [obs(A, h=True), obs(B, h=True)])
        self.assertEqual(sim.states[A]["step"], REBOOT)
        v = sim.step(T0 + 900, [obs(A, h=True), obs(B, h=True)])
        self.assertIn("reset", kinds(v, A))
        self.assertEqual(sim.states[A]["step"], 0)

    def test_a_blip_does_not_reset_escalation(self):
        sim = Sim(A, B)
        sim.step(T0, [obs(A, connect=True), obs(B, h=True)])
        sim.step(T0 + 120, [obs(A, connect=True), obs(B, h=True)])
        sim.step(T0 + 300, [obs(A, h=True), obs(B, h=True)])
        # Bad again before 600 s healthy: no fresh grace, the ladder continues at step 2.
        v = sim.step(T0 + 600, [obs(A, connect=True), obs(B, h=True)])
        self.assertEqual(acts(v), [(A, REBOOT)])

    def test_unknown_never_acts_and_regraces_after_outage(self):
        sim = Sim(A, B)
        sim.step(T0, [obs(A), obs(B, h=True)])
        v = sim.step(T0 + 200, [obs(A, h=None), obs(B, h=None)])
        self.assertEqual(acts(v), [])
        self.assertEqual(kinds(v, A), ["hold"])
        # Broker back: still 300 s of observation before anything is tried.
        sim.step(T0 + 210, [obs(A), obs(B, h=True)])
        self.assertEqual(acts(sim.step(T0 + 499, [obs(A), obs(B, h=True)])), [])
        self.assertEqual(acts(sim.step(T0 + 500, [obs(A), obs(B, h=True)])), [(A, POE)])

    def test_unknown_link_holds(self):
        sim = Sim(A, B)
        sim.step(T0, [obs(A, l=None), obs(B, h=True)])
        self.assertEqual(acts(sim.step(T0 + 1000, [obs(A, l=None), obs(B, h=True)])), [])

    def test_site_unknown_holds_everything(self):
        sim = Sim(A, B)
        sim.step(T0, [obs(A), obs(B, h=True)])
        self.assertEqual(acts(sim.step(T0 + 500, [obs(A), obs(B, h=True)], site_unknown="broker")), [])

    def test_circuit_breaker(self):
        sim = Sim(A, B, C)
        for t in (T0, T0 + 1000):
            v = sim.step(t, [obs(A), obs(B), obs(C, h=True)])
        self.assertEqual(acts(v), [])
        self.assertTrue(any(x.kind == "breaker" for x in v))

    def test_two_screens_both_quiet_trip_the_breaker(self):
        sim = Sim(A, B)
        for t in (T0, T0 + 1000):
            v = sim.step(t, [obs(A), obs(B)])
        self.assertEqual(acts(v), [])
        self.assertTrue(any(x.kind == "breaker" for x in v))

    def test_single_screen_escalates_without_breaker(self):
        sim = Sim(A)
        sim.step(T0, [obs(A, connect=True)])
        v = sim.step(T0 + 120, [obs(A, connect=True)])
        self.assertFalse(any(x.kind == "breaker" for x in v))
        self.assertEqual(acts(v), [(A, RESTORE)])
        self.assertEqual(acts(sim.step(T0 + 240, [obs(A, connect=True)])), [(A, REBOOT)])

    def test_quiet_screens_without_link_are_not_a_site_problem(self):
        sim = Sim(A, B, C)
        sim.step(T0, [obs(A, l=False), obs(B, l=False), obs(C, h=True)])
        v = sim.step(T0 + 1000, [obs(A, l=False), obs(B, l=False), obs(C, h=True)])
        self.assertFalse(any(x.kind == "breaker" for x in v))
        self.assertEqual(len(acts(v)), 1)  # serialized: one recovery at a time

    def test_held_and_paused_screens_do_not_act(self):
        sim = Sim(A, B)
        sim.step(T0, [obs(A, held="topology"), obs(B, h=True)])
        self.assertEqual(acts(sim.step(T0 + 500, [obs(A, held="topology"), obs(B, h=True)])), [])
        self.assertEqual(acts(sim.step(T0 + 600, [obs(A), obs(B, h=True)], paused=True)), [])


# ---- fakes for the consoles ------------------------------------------------------

def port(idx, up=True, **kw):
    return {"port_idx": idx, "up": up, "poe_caps": 7, "poe_enable": True, **kw}


class FakeNetwork:
    def __init__(self, clients=None, devices=None):
        self._clients = clients if clients is not None else [
            {"mac": A, "ip": "10.0.0.11", "sw_mac": SW, "sw_port": 1, "is_wired": True},
            {"mac": B, "ip": "10.0.0.12", "sw_mac": SW, "sw_port": 2, "is_wired": True},
        ]
        self._devices = devices if devices is not None else [
            {"mac": SW, "name": "Switch", "last_seen": T0, "port_table": [port(1), port(2), port(9, is_uplink=True)]},
        ]
        self.power_cycles = []

    def clients(self):
        return list(self._clients)

    def devices(self):
        return list(self._devices)

    def power_cycle(self, *args):
        self.power_cycles.append(args)
        raise AssertionError("power_cycle must never be called in 0.1.0b1")

    def close(self):
        pass


def enroll(mac=B, port_idx=2, **kw):
    return Enrollment.objects.create(console="192.168.1.1:443", mac=mac, switch_mac=SW,
                                     switch_port=port_idx, **kw)


class ExecutorTests(TestCase):
    def setUp(self):
        self.now = _dt(T0)
        self.net = FakeNetwork()

    def run_step(self, enr, step=POE, origin="auto", **kw):
        kw.setdefault("network", self.net)
        return executor.execute(enr.pk, step, origin=origin, now=kw.pop("now", self.now), **kw)

    def test_dry_run_records_interlock_and_dispatches_nothing(self):
        out = self.run_step(enroll())
        self.assertEqual(out.status, Action.DRY_RUN)
        self.assertTrue(out.evidence["interlock"]["ok"])
        self.assertEqual(self.net.power_cycles, [])

    def test_interlock_refusal_is_recorded_in_dry_run(self):
        self.net._clients.append({"mac": C, "sw_mac": SW, "sw_port": 2})
        out = self.run_step(enroll())
        self.assertEqual(out.status, Action.REFUSED)
        self.assertIn("other clients", out.reason)
        self.assertFalse(out.evidence["interlock"]["ok"])

    def test_live_actions_guard(self):
        self.assertFalse(executor.LIVE_ACTIONS_ALLOWED)
        out = self.run_step(enroll(), live=True)
        self.assertEqual(out.status, Action.REFUSED)
        self.assertEqual(self.net.power_cycles, [])
        client = NetworkClient("https://192.0.2.1", "default", "key", "0" * 64)
        with mock.patch.object(client.session, "request") as request:
            with self.assertRaises(LiveActionsDisabled):
                client.power_cycle(SW, 2)
            request.assert_not_called()

    def test_pause_cancels_a_queued_action(self):
        out = self.run_step(enroll(), _after_reserve=lambda a: executor.pause(self.now, 3600))
        self.assertEqual(out.status, Action.CANCELLED)
        self.assertEqual(Action.objects.get().status, Action.CANCELLED)
        self.assertEqual(self.net.power_cycles, [])

    def test_pause_expires(self):
        executor.pause(self.now, 3600)
        self.assertTrue(executor.pause_state(self.now)[0])
        self.assertFalse(executor.pause_state(self.now + timedelta(seconds=3601))[0])

    def test_manual_and_automatic_race(self):
        enr = enroll()
        first = self.run_step(enr, origin="auto")
        second = self.run_step(enr, origin="manual", now=self.now + timedelta(seconds=5))
        self.assertEqual(first.status, Action.DRY_RUN)
        self.assertEqual(second.status, Action.REFUSED)
        self.assertIn("observe window", second.reason)

    def test_restart_between_reservation_and_dispatch(self):
        enr = enroll()

        def crash(action):
            raise KeyboardInterrupt  # the process dies right after reserving

        with self.assertRaises(KeyboardInterrupt):
            self.run_step(enr, _after_reserve=crash)
        self.assertEqual(Action.objects.get().status, Action.RESERVED)
        executor.recover_after_restart(self.now)
        self.assertEqual(Action.objects.get().status, Action.ABANDONED)
        # The abandoned reservation was never dispatched, so it uses up nothing.
        self.assertEqual(self.run_step(enr).status, Action.DRY_RUN)

    def test_possibly_executed_counts_against_the_window(self):
        enr = enroll()
        Action.objects.create(enrollment=enr, mac=enr.mac, step=POE, origin="auto", mode="dry_run",
                              status=Action.DISPATCHING, created_at=self.now, updated_at=self.now)
        executor.recover_after_restart(self.now)
        self.assertEqual(Action.objects.get().status, Action.POSSIBLY_EXECUTED)
        self.assertEqual(self.run_step(enr).status, Action.REFUSED)

    def test_poe_budget_per_day(self):
        enr = enroll()
        for i in range(executor.MAX_POE_PER_DAY):
            at = self.now - timedelta(hours=1, minutes=i)
            Action.objects.create(enrollment=enr, mac=enr.mac, step=POE, origin="auto", mode="dry_run",
                                  status=Action.DRY_RUN, created_at=at, updated_at=at)
        out = self.run_step(enr)
        self.assertEqual(out.status, Action.REFUSED)
        self.assertIn("budget", out.reason)
        # Live budget is separate from dry-run counters.
        self.assertEqual(executor.poe_used(enr.mac, "live", self.now), 0)

    def test_topology_hold_cancels(self):
        out = self.run_step(enroll(topology_hold=True))
        self.assertEqual(out.status, Action.CANCELLED)


class InterlockTests(SimpleTestCase):
    def check(self, clients, devices=None, mac=B, port_idx=2, now=T0):
        net = FakeNetwork(clients, devices)
        return interlock.check(screen_mac=mac, switch_mac=SW, switch_port=port_idx,
                               clients=net.clients(), devices=net.devices(), now=now)[:2]

    def test_rules(self):
        on_port = [{"mac": B, "sw_mac": SW, "sw_port": 2}]
        self.assertTrue(self.check(on_port)[0])
        self.assertFalse(self.check(on_port, port_idx=9)[0])  # uplink
        self.assertFalse(self.check([{"mac": B, "sw_mac": SW, "sw_port": 1}])[0])  # elsewhere
        self.assertTrue(self.check([])[0])  # absent, port empty, switch fresh
        self.assertFalse(self.check([], now=T0 + 1000)[0])  # absent, switch record stale
        self.assertFalse(self.check([{"mac": C, "sw_mac": SW, "sw_port": 2}])[0])
        no_poe = [{"mac": SW, "last_seen": T0, "port_table": [{"port_idx": 2, "up": True}]}]
        self.assertFalse(self.check(on_port, no_poe)[0])


class ObserveTests(SimpleTestCase):
    def enr(self, **kw):
        return Enrollment(console="c", mac=B, switch_mac=SW, switch_port=2, ip="10.0.0.12", **kw)

    def observe(self, enr, clients, beats, **kw):
        net = FakeNetwork(clients)
        kw.setdefault("connect_state", "off")
        return service.observe(enr, h_state="ok", beats=beats, ready_age=3600,
                               net=(net.clients(), net.devices()), connect_devs=None, **kw)

    def test_dhcp_reuse_does_not_borrow_another_screens_heartbeat(self):
        # Our screen is gone and its old IP now belongs to another device that is checking in.
        clients = [{"mac": C, "ip": "10.0.0.12", "sw_mac": SW, "sw_port": 5}]
        o, _ = self.observe(self.enr(), clients, {"10.0.0.12": 5})
        self.assertIs(o.h, False)
        self.assertIs(o.l, False)
        self.assertEqual(o.evidence["ip_reused_by"], C)

    def test_heartbeat_is_matched_by_the_current_ip(self):
        clients = [{"mac": B, "ip": "10.0.0.50", "sw_mac": SW, "sw_port": 2}]
        o, updates = self.observe(self.enr(), clients, {"10.0.0.12": 5, "10.0.0.50": 400})
        self.assertIs(o.h, False)
        self.assertEqual(updates["ip"], "10.0.0.50")

    def test_port_move_holds_recovery(self):
        clients = [{"mac": B, "ip": "10.0.0.12", "sw_mac": SW, "sw_port": 1}]
        o, updates = self.observe(self.enr(), clients, {})
        self.assertTrue(updates["topology_hold"])
        self.assertEqual(updates["observed_switch_port"], 1)
        self.assertTrue(o.held)
        _, verdicts = engine.decide(T0 + 1000, [({"bad_since": T0}, o), ({}, obs(A, h=True))])
        self.assertEqual(acts(verdicts), [])

    def test_offline_client_missing_from_topology_is_bad(self):
        o, updates = self.observe(self.enr(), [], {})
        self.assertIs(o.l, False)
        self.assertIs(o.h, False)
        self.assertEqual(engine.health(o), engine.BAD)
        self.assertNotIn("topology_hold", updates)

    def test_hub_just_started_is_unknown(self):
        clients = [{"mac": B, "ip": "10.0.0.12", "sw_mac": SW, "sw_port": 2}]
        o, _ = service.observe(self.enr(), h_state="ok", beats={}, ready_age=60,
                               net=(clients, FakeNetwork().devices()), connect_state="off", connect_devs=None)
        self.assertIsNone(o.h)


# ---- the loop ---------------------------------------------------------------------

def settings_with(values):
    return lambda app, key, default="", **kw: values.get(key, default)


@mock.patch("unifi_screens.notify.app_setting", settings_with({}))
class WatchdogTests(TestCase):
    def dog(self, clock, displays, net=None):
        net = net or FakeNetwork()
        return service.Watchdog(clock=clock, displays=displays,
                                network=lambda now: (net, "ok", ""),
                                connect=lambda now: (None, "off", "not configured")), net

    @mock.patch("unifi_screens.service.app_setting", settings_with({"enabled": "1"}))
    def test_dry_run_end_to_end(self):
        enroll(A, 1)
        enroll(B, 2)
        t = [T0]
        displays = lambda: {"ready_since": _dt(T0 - 3600), "now": _dt(t[0]),
                            "clients": [{"ip": "10.0.0.11", "age_seconds": 10},
                                        {"ip": "10.0.0.12", "age_seconds": 900}]}
        dog, net = self.dog(lambda: t[0], displays)
        dog.tick()
        self.assertFalse(Action.objects.exists())
        t[0] += 130
        dog.tick()
        action = Action.objects.get()
        self.assertEqual((action.mac, action.step, action.status), (B, POE, Action.DRY_RUN))
        self.assertIn("Would PoE power-cycle", Enrollment.objects.get(mac=B).last_decision)
        self.assertEqual(net.power_cycles, [])

    @mock.patch("unifi_screens.service.app_setting", settings_with({"enabled": "1"}))
    def test_displays_unsupported_or_denied_disables_recovery(self):
        from bdh_sdk.rpc import BrokerError, PermissionDenied

        enroll()
        for exc, state in ((BrokerError("no op", "not_found", 404), "unsupported"),
                           (PermissionDenied("no", "forbidden", 403), "denied")):
            def displays(exc=exc):
                raise exc

            dog, _ = self.dog(lambda: T0 + 10_000, displays)
            status = dog.tick()
            self.assertEqual(status["displays"]["state"], state)
            self.assertIn("recovery disabled", status["disabled_reason"])
            self.assertTrue(Incident.objects.filter(kind="displays", key=state, open=True).exists())
        self.assertFalse(Action.objects.exists())

    def test_no_broker_means_unsupported(self):
        state, _, _, _ = service.read_displays()
        self.assertEqual(state, "unsupported")

    @mock.patch("unifi_screens.service.app_setting", settings_with({"enabled": "1"}))
    def test_broker_outage_holds(self):
        from bdh_sdk.rpc import BrokerError

        enroll(A, 1)
        enroll(B, 2)

        def displays():
            raise BrokerError("down", "unreachable", 502)

        dog, _ = self.dog(lambda: T0 + 10_000, displays)
        status = dog.tick()
        self.assertEqual(status["displays"]["state"], "unavailable")
        self.assertFalse(Action.objects.exists())


# ---- TLS pinning -------------------------------------------------------------------

def _self_signed(path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.test")])
    now = datetime.now(dt_tz.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    with open(path / "cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(path / "key.pem", "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))


class TlsServer:
    """A one-thread HTTPS server that records every byte it receives."""

    BODY = b'{"meta":{"rc":"ok"},"data":[]}'

    def __init__(self, folder):
        _self_signed(folder)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(folder / "cert.pem", folder / "key.pem")
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.url = f"https://127.0.0.1:{self.sock.getsockname()[1]}"
        self.received = b""
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop:
            try:
                raw, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                raw.settimeout(2)
                with self.ctx.wrap_socket(raw, server_side=True) as tls:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    self.received += data
                    if data:
                        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                    b"Connection: close\r\nContent-Length: %d\r\n\r\n%s"
                                    % (len(self.BODY), self.BODY))
            except (OSError, ssl.SSLError):
                pass

    def close(self):
        self._stop = True
        self.thread.join(2)
        self.sock.close()


@skipUnless(x509, "cryptography not installed")
class PinningTests(SimpleTestCase):
    def setUp(self):
        import pathlib
        import tempfile

        self._dir = tempfile.TemporaryDirectory()
        self.server = TlsServer(pathlib.Path(self._dir.name))
        self.addCleanup(self._dir.cleanup)
        self.addCleanup(self.server.close)

    def test_mismatch_refuses_before_sending_credentials(self):
        client = NetworkClient(self.server.url, "default", "SECRET-KEY", "ab" * 32)
        with self.assertRaises(UnifiError) as caught:
            client.clients()
        self.assertEqual(caught.exception.kind, "pin")
        time.sleep(0.3)
        self.assertNotIn(b"SECRET-KEY", self.server.received)
        self.assertEqual(self.server.received, b"")

    def test_matching_pin_talks_to_the_console(self):
        fp = fetch_fingerprint(self.server.url)
        client = NetworkClient(self.server.url, "default", "SECRET-KEY", fp)
        self.assertEqual(client.clients(), [])
        self.assertIn(b"X-API-KEY: SECRET-KEY", self.server.received)

    def test_other_hosts_are_never_contacted(self):
        fp = fetch_fingerprint(self.server.url)
        client = NetworkClient(self.server.url, "default", "SECRET-KEY", fp)
        with self.assertRaises(Exception):
            client.session.get("https://192.0.2.1/", timeout=1)


# ---- views and manifest ---------------------------------------------------------------

class ViewTests(TestCase):
    def setUp(self):
        self.url = reverse("unifi_screens_settings")
        users = get_user_model()
        self.user = users.objects.create_user("guest", password="pw")
        self.admin = users.objects.create_user("boss", password="pw", is_staff=True)

    def test_admins_only(self):
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.url, {"action": "pause", "length": "1h"}).status_code, 403)
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertFalse(executor.pause_state(_dt(time.time()))[0])

    def test_admin_page_shows_dry_run_banner(self):
        self.client.force_login(self.admin)
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Dry run: this version only records what it would do.")

    def test_admin_pause_and_resume(self):
        self.client.force_login(self.admin)
        self.client.post(self.url, {"action": "pause", "length": "4h"})
        self.assertTrue(executor.pause_state(_dt(time.time()))[0])
        self.client.post(self.url, {"action": "resume"})
        self.assertFalse(executor.pause_state(_dt(time.time()))[0])


class PluginTests(SimpleTestCase):
    def test_plugin_importable(self):
        from bdh_sdk.testing import assert_plugin_importable

        assert_plugin_importable("unifi_screens.plugin")
