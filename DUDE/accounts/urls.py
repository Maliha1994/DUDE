from django.contrib import admin
from django.urls import path

from django.contrib import admin
from django.urls import path
from .views import user_login,register,user_logout
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('register/', register, name='register'),
    path('', user_login, name='login'),
    path('logout/', user_logout, name='logout-page'),
]
