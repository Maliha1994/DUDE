from django.db import models
from django.core.validators import FileExtensionValidator

class FeastModel(models.Model):
    firm_img = models.FileField(verbose_name="", default=0,
                                validators=[FileExtensionValidator(allowed_extensions=["bin"])])

    def __str__(self):
        return str(self.id)
