from django import forms
from django.contrib.auth.forms import UserCreationForm

class RegistrationForm(UserCreationForm):
    # Add any additional fields you need for registration
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
