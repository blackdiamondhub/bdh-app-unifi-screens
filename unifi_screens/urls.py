from django.urls import path

from . import views

urlpatterns = [
    path("settings/", views.settings_page, name="unifi_screens_settings"),
]
