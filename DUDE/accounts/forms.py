from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from crispy_forms.helper import FormHelper
from django import forms
from django.core.exceptions import ValidationError



class UserRegisterForm(UserCreationForm):

    username = forms.CharField(widget=forms.TextInput)
    email = forms.EmailField()
    password1 = forms.CharField(label='Enter Password', widget=forms.PasswordInput())
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput())

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def clean_email(self):
        email = self.cleaned_data["email"]
        if User.objects.filter(email=email).exists():
            raise ValidationError("An user with this email already exists!")
        return email



# from django.core.exceptions import ValidationError
#
#
# class UserRegisterForm(UserCreationForm):
#
#     class Meta:
#         model = User
#         fields = ['username', 'email', 'password1', 'password2']
#
#     def clean_email(self):
#         email = self.cleaned_data["email"]
#         if User.objects.filter(email=email).exists():
#             raise ValidationError("An user with this email already exists!")
#         return email
#
#
#


