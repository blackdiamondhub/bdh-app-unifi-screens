from django.db import models


class Enrollment(models.Model):
    """A screen an admin approved for recovery: one console + one MAC."""

    console = models.CharField(max_length=200)
    mac = models.CharField(max_length=17)
    name = models.CharField(max_length=100, blank=True)
    connect_id = models.CharField(max_length=64, blank=True)
    switch_mac = models.CharField(max_length=17)
    switch_port = models.IntegerField()
    ip = models.CharField(max_length=45, blank=True)
    # The screen showed up on another switch/port: recovery held until re-approved.
    topology_hold = models.BooleanField(default=False)
    observed_switch_mac = models.CharField(max_length=17, blank=True)
    observed_switch_port = models.IntegerField(null=True, blank=True)
    state = models.JSONField(default=dict)
    last_h = models.CharField(max_length=8, blank=True)
    last_l = models.CharField(max_length=8, blank=True)
    last_connect = models.CharField(max_length=8, blank=True)
    last_decision = models.CharField(max_length=300, blank=True)
    last_decision_at = models.DateTimeField(null=True, blank=True)
    enrolled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("console", "mac"),)
        ordering = ("name", "mac")

    def __str__(self):
        return self.name or self.mac


class Action(models.Model):
    """One (would-be) destructive action, reserved before it is dispatched."""

    RESERVED = "reserved"
    DISPATCHING = "dispatching"
    DRY_RUN = "dry_run"
    DONE = "done"
    REFUSED = "refused"
    CANCELLED = "cancelled"
    ABANDONED = "abandoned"
    POSSIBLY_EXECUTED = "possibly_executed"
    FAILED = "failed"

    enrollment = models.ForeignKey(Enrollment, null=True, blank=True, on_delete=models.SET_NULL)
    mac = models.CharField(max_length=17)
    step = models.IntegerField()
    origin = models.CharField(max_length=10)  # auto / manual
    mode = models.CharField(max_length=10)  # dry_run / live
    status = models.CharField(max_length=20, default=RESERVED)
    reason = models.CharField(max_length=300, blank=True)
    evidence = models.JSONField(default=dict)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()

    class Meta:
        ordering = ("-created_at", "-id")


class Decision(models.Model):
    """What the engine decided for a screen on a loop, with its evidence."""

    at = models.DateTimeField()
    mac = models.CharField(max_length=17, blank=True)
    kind = models.CharField(max_length=20)
    step = models.IntegerField(null=True, blank=True)
    reason = models.CharField(max_length=300, blank=True)
    evidence = models.JSONField(default=dict)

    class Meta:
        ordering = ("-at", "-id")


class Incident(models.Model):
    kind = models.CharField(max_length=30)
    key = models.CharField(max_length=120)
    mac = models.CharField(max_length=17, blank=True)
    title = models.CharField(max_length=200)
    message = models.TextField(blank=True)
    first_at = models.DateTimeField()
    last_at = models.DateTimeField()
    count = models.IntegerField(default=1)
    open = models.BooleanField(default=True)
    notified_at = models.DateTimeField(null=True, blank=True)
    notify_error = models.CharField(max_length=300, blank=True)

    class Meta:
        ordering = ("-open", "-last_at", "-id")
        indexes = [models.Index(fields=("kind", "key", "open"))]


class Pause(models.Model):
    """Singleton (pk=1). ``until`` None while active means until resumed."""

    active = models.BooleanField(default=False)
    until = models.DateTimeField(null=True, blank=True)
    since = models.DateTimeField(null=True, blank=True)


class Pin(models.Model):
    """TOFU certificate pin for a console (service = network / connect)."""

    service = models.CharField(max_length=20, unique=True)
    host = models.CharField(max_length=200, blank=True)
    fingerprint = models.CharField(max_length=64, blank=True)
    trusted_at = models.DateTimeField(null=True, blank=True)
    pending = models.CharField(max_length=64, blank=True)
    pending_at = models.DateTimeField(null=True, blank=True)


class Kv(models.Model):
    """Small JSON blobs the worker writes for the settings page (status, candidates)."""

    key = models.CharField(max_length=40, unique=True)
    value = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)
