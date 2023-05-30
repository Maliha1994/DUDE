from django.db import models

# Create your models here.


class Repository(models.Model):
    manufacturer = models.TextField()
    title = models.TextField()
    version = models.TextField()
    link = models.URLField()
    download_url = models.URLField()

    def __str__(self):
        return self.manufacturer