from bdh_sdk import PluginSpec, Setting, SettingsPage
from bdh_sdk.plugins import BOOL, LIFECYCLE_ALWAYS, NETWORK_LAN, SECRET

spec = PluginSpec(
    id="unifi_screens",
    app="unifi_screens",
    urls="unifi_screens.urls",
    url_prefix="unifi-screens/",
    # No tiles, status hook, card or shortcuts: the watchdog has no on-screen UI.
    settings=(
        Setting("enabled", "Watch screens", type=BOOL, default=False,
                help="Off: the app only reads the consoles to list screens."),
        Setting("network_url", "UniFi Network console",
                help="The gateway running UniFi Network, e.g. https://192.168.1.1"),
        Setting("network_site", "Network site", default="default"),
        Setting("network_api_key", "Network API key", type=SECRET,
                help="Control Plane > Integrations. The key has full admin rights on the console."),
        Setting("connect_url", "UniFi Connect console",
                help="Optional. The console running UniFi Connect, e.g. https://192.168.1.26"),
        Setting("connect_username", "Connect username",
                help="A local user on the Connect console."),
        Setting("connect_password", "Connect password", type=SECRET),
        Setting("notify_service", "Phone notify service",
                help="Home Assistant notify service for incidents, e.g. notify.mobile_app_pixel"),
    ),
    settings_pages=(
        SettingsPage("Screens", "unifi_screens_settings",
                     subtitle="Enrolled screens, consoles, incidents and decisions",
                     icon="fas fa-display"),
    ),
    api_version=2,
    # Heartbeats of the screens, admin pop-ups for incidents, phone notify.
    permissions=("displays.read", "alerts", "ha.call:notify.*"),
    # Talks to the UniFi Network and Connect consoles on the LAN.
    network=NETWORK_LAN,
    # A watchdog has to keep watching.
    lifecycle=LIFECYCLE_ALWAYS,
    memory_mb=96,
)
