from django import forms
from feast_app.models import FeastModel


class FeastForm(forms.ModelForm):
    class Meta:
        model = FeastModel
        fields = ('firm_img',)
