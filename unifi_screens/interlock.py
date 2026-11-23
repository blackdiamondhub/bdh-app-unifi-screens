"""PoE interlock: may this enrolled screen's switch port be power-cycled?

Kept small and isolated on purpose: the exact ``stat/sta``/``stat/device``
behaviour while a screen is unplugged, booting or moved still has to be
pinned down with read-only captures, and the rules will be tightened then.
"""

SWITCH_FRESH_S = 180  # the switch record must be this recent when the screen is absent


def norm_mac(mac):
    return (mac or "").strip().lower().replace("-", ":")


def port_entry(device, port_idx):
    for port in device.get("port_table") or ():
        if port.get("port_idx") == port_idx:
            return port
    return None


def poe_capable(port):
    return bool(port.get("port_poe") or port.get("poe_caps") or "poe_enable" in port)


def check(*, screen_mac, switch_mac, switch_port, clients, devices, now):
    """``(ok, reason, evidence)`` for power-cycling ``switch_mac`` port ``switch_port``.

    ``clients``/``devices`` are a fresh ``stat/sta``/``stat/device`` read.
    """
    screen_mac, switch_mac = norm_mac(screen_mac), norm_mac(switch_mac)
    evidence = {"switch_mac": switch_mac, "switch_port": switch_port, "screen_mac": screen_mac}
    device = next((d for d in devices if norm_mac(d.get("mac")) == switch_mac), None)
    if device is None:
        return False, "approved switch not found", evidence
    port = port_entry(device, switch_port)
    if port is None:
        return False, f"port {switch_port} not on the approved switch", evidence
    evidence["port"] = {k: port.get(k) for k in ("up", "poe_enable", "poe_caps", "port_poe",
                                                   "is_uplink", "poe_mode")}
    if not poe_capable(port):
        return False, "port is not PoE-capable", evidence
    if port.get("is_uplink"):
        return False, "port is an uplink", evidence

    on_port = sorted(norm_mac(c.get("mac")) for c in clients
                     if norm_mac(c.get("sw_mac")) == switch_mac and c.get("sw_port") == switch_port)
    screen = next((c for c in clients if norm_mac(c.get("mac")) == screen_mac), None)
    evidence["clients_on_port"] = on_port
    evidence["screen_visible"] = screen is not None
    others = [m for m in on_port if m != screen_mac]
    if screen is not None:
        if (norm_mac(screen.get("sw_mac")), screen.get("sw_port")) != (switch_mac, switch_port):
            return False, "screen is on another switch/port", evidence
        if others:
            return False, "other clients on the port", evidence
        return True, "screen is the only client on the approved port", evidence
    if others:
        return False, "screen absent and another client is on the port", evidence
    last_seen = device.get("last_seen")
    evidence["switch_last_seen"] = last_seen
    if not isinstance(last_seen, (int, float)) or now - last_seen > SWITCH_FRESH_S:
        return False, "switch record is stale", evidence
    return True, "screen absent, no other client on the approved port", evidence
