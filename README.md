# UniFi Screens watchdog (BlackDiamondHub app)

An optional BlackDiamondHub store app that watches the UniFi Connect kiosk
screens showing the hub. When a screen stops checking in, it works out why and
recovers it. It replaces the old AppDaemon watchdog. The design is in the hub
repo: `docs/unifi-screens-watchdog-design.md`.

> **Status: 0.1.0b1, dry run only.** This version discovers screens, lets you
> enroll them, and runs the full decision engine. It only **records** what it
> would do ("would restore kiosk", "would reboot", "would PoE power-cycle"),
> with the evidence. It never sends a Connect action or a PoE power-cycle.
> Live actions are hard-disabled (`executor.LIVE_ACTIONS_ALLOWED = False`).

## What it does

Every 30 s the worker looks at:

- **H (heartbeat):** has the screen's current IP checked in with the hub in the
  last 5 minutes? It reads this from the hub broker (`displays.status`, permission
  `displays.read`). It never uses the open `/display/api/heartbeats/` endpoint.
- **L (link):** does UniFi Network see the screen as a client, and is its switch
  port up?
- **Connect:** does the device show up in UniFi Connect? This is optional.

A screen that is quiet while its link is up gets a 120 s grace period. Then it
climbs a ladder:

1. Restore the kiosk (needs Connect). Then watch for 120 s.
2. Reboot through Connect. Then watch for 240 s.
3. Power-cycle its PoE switch port. Then watch for 240 s.

After 3 PoE cycles without recovery it gives up and raises an incident. The
escalation resets after 10 minutes of continuous health.

Safety rules:

- **Unknown never acts.** If the broker or the Network console is down, nothing
  happens. After any outage there are 5 minutes of observation first.
- **Circuit breaker.** With two or more enrolled screens, if two or more go
  quiet together while the network still sees them, the hub is the likely
  problem. It raises an alert and touches nothing. With a single enrolled
  screen there is no breaker; hub-wide failures are still covered because H is
  Unknown while the broker is unreachable or the hub has just started, plus the
  caps below.
- **One recovery at a time.** At most one action per screen per observe window,
  and at most 6 PoE cycles per screen per day.
- **PoE interlock.** The approved switch and port must match. The port must be
  PoE-capable and not an uplink. The screen must be the only client on it.
- **Topology changes hold recovery.** If a screen moves to another switch or
  port, recovery stops until an admin re-approves it.
- **Pause.** You can pause for 1 h, for 4 h, or until resumed.

**No on-screen UI, by design.** The app has no tiles, cards, shortcuts or
homepage items. Everything lives on its settings page (**Settings → UniFi Screens
→ Screens**, staff only). Incidents can also go to your phone through a Home
Assistant notify service.

## Setup

1. Install the app from the hub's store. It runs in its own container. It needs
   the broker's `displays.status` operation (bdh-sdk ≥ 0.43 on the hub).
2. **UniFi Network:** in the gateway's UniFi OS, go to *Settings → Control Plane →
   Integrations* and create an API key.
   - The key has **full admin rights on that console**. Treat it like a password.
   - Set `network_url` (for example `https://192.168.1.1`), `network_api_key`,
     and `network_site` if yours isn't `default`.
3. **UniFi Connect (optional):** set `connect_url` (the console running Connect,
   for example `https://192.168.1.26`), `connect_username` and `connect_password`.
   - Use a dedicated local account.
   - Without Connect, only the PoE step is possible.
4. Optional: set `notify_service`, for example `notify.mobile_app_pixel`. Use
   **Send test** on the settings page to check it.
5. Turn `enabled` on.
6. Open the Screens page and trust each console's certificate (see below).
7. Enroll the discovered screens. Discovery joins hub heartbeats to Network
   clients, then to Connect devices. Enrolling approves the switch and port the
   screen is on now.

### Certificate trust (TOFU)

UniFi consoles use self-signed certificates, so the app pins them on first use:

- The first time it connects, it records the certificate's SHA-256 fingerprint
  as *pending*. Nothing else is sent.
- **Compare the fingerprint shown on the settings page with the one on the
  console before you click Trust.** If you trust the wrong one, a device in the
  middle could collect the API key or password.
- After that, every connection checks the fingerprint before any credentials
  are sent. If it changes, the app raises an incident and sends nothing. It
  only re-pins when an admin clicks **Re-pin**.

## Development

Tests run inside a hub checkout the way the reusable CI does:

```
python manage.py test unifi_screens --exclude-tag=selenium
```

## License

MIT
