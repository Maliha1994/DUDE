from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import path, include

from feast_app import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include("accounts.urls")),
    path('feast/', views.index, name='index'),
    path('upload/', views.nav_upload, name='nav_upload'),

    path('uploaded/', views.run_upload, name='run_upload'),
    path('unpack/', views.nav_unpack, name='nav_unpack'),
    path('unpacked/', views.run_unpack, name='run_unpack'),
    path('stat/', views.nav_static, name='nav_static'),

    # path("static/", views.nav_static, name='nav_static'),
    # path('upload/uploaded/unpack/unpacked/static/', views.nav_static, name='nav_static'),
    path('staticed/', views.run_static, name='run_static'),
    path('dynamic/', views.nav_dynamic, name='nav_dynamic'),
    path('dynamiced/', views.run_dynamic, name='run_dynamic'),
    path('report/', views.nav_report, name='nav_report'),
    path('reported/', views.run_report, name='run_report'),
    path('sendmail/', views.email_sender, name='sendmail'),
    path('static_analysis/', views.staticAnalysis, name='static_analysis'),
    path('ai/', views.ai, name='ai'),
    path('run_img_upload', views.run_img_upload, name='run_img_upload'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += staticfiles_urlpatterns()
