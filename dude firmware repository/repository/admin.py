from django.contrib import admin
from .models import Repository
# Register your models here.
admin.site.site_header= "Repository Admin"
admin.site.site_title= "Repository Admin"

admin.site.register(Repository)