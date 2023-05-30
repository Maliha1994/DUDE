from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', views.admin),
    path('', views.index,name='index'),
    path('get_started/', views.get_started,name='get_started'),
    path('result/', views.result, name='result')
]
