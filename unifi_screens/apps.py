from django.apps import AppConfig


class UnifiScreensConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "unifi_screens"
    verbose_name = "UniFi Screens"

    def ready(self):
        from . import worker

        if worker.should_start():
            worker.start()
