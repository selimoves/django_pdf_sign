"""URL приложения примера."""

from django.urls import path

from signatures import views

urlpatterns = [
    path("", views.index, name="index"),
    path("upload/", views.upload, name="upload"),
    path("prepare/<int:pk>/", views.prepare, name="prepare"),
    path("complete/<uuid:session_id>/", views.complete, name="complete"),
]
