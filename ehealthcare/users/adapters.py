# filepath: c:\Users\Anish\Desktop\Final Year Project\ehealthcare\users\adapters.py
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.utils.text import slugify
import random
import string

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        if not user.username:
            user.username = slugify(data.get('name', '')) or ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return user