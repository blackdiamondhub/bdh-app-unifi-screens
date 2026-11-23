"""Discovery: propose screens to enroll by joining what the consoles see.

heartbeat IP -> Network client (MAC, switch, port) -> Connect device (by MAC, then IP).
Pure; nothing is enrolled without an admin clicking Enroll.
"""
from .interlock import norm_mac
from .unifi import connect_ip, connect_mac


def candidates(heartbeats, clients, connect_devices, enrolled_macs):
    """``heartbeats`` is ``{ip: age_seconds}``. Returns a list of plain dicts."""
    by_ip = {}
    for c in clients:
        if c.get("ip"):
            by_ip[c["ip"]] = c
    by_mac = {connect_mac(d): d for d in connect_devices if connect_mac(d)}
    by_cip = {connect_ip(d): d for d in connect_devices if connect_ip(d)}
    enrolled = {norm_mac(m) for m in enrolled_macs}
    out = []
    for ip, age in sorted(heartbeats.items()):
        client = by_ip.get(ip)
        if client is None:
            continue
        mac = norm_mac(client.get("mac"))
        if not mac or mac in enrolled:
            continue
        dev = by_mac.get(mac) or by_cip.get(ip)
        wired = client.get("is_wired", True) and client.get("sw_mac") and client.get("sw_port") is not None
        out.append({
            "mac": mac, "ip": ip, "heartbeat_age": age,
            "name": (dev or {}).get("name") or client.get("name") or client.get("hostname") or "",
            "switch_mac": norm_mac(client.get("sw_mac")) if wired else "",
            "switch_port": client.get("sw_port") if wired else None,
            "connect_id": str((dev or {}).get("id") or ""),
            "problem": "" if wired else "not wired to a switch port (PoE recovery impossible)",
        })
    return out
