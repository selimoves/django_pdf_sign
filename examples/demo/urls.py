"""URL демонстрационного проекта."""

from django.urls import include, path

urlpatterns = [
    path("", include("signatures.urls")),
]
