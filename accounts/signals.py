from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from allauth.socialaccount.signals import social_account_added, pre_social_login
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import HttpResponseRedirect
import json
import urllib.parse

User = get_user_model()


@receiver(post_save, sender=SocialAccount)
def update_user_auth_provider(sender, instance, created, **kwargs):
    """Update user auth_provider when social account is created."""
    user = instance.user
    provider = instance.provider
    
    if provider == 'google' and user.auth_provider == 'email':
        user.auth_provider = 'google'
        user.is_email_verified = True
        user.save()
    elif provider == 'github' and user.auth_provider == 'email':
        user.auth_provider = 'github'
        user.is_email_verified = True
        user.save()


@receiver(social_account_added)
def store_provider_in_session(sender, request, sociallogin, **kwargs):
    """Store provider in session for redirect URL generation."""
    if request and hasattr(request, 'session') and sociallogin.account:
        request.session['socialaccount_provider'] = sociallogin.account.provider
        request.session.modified = True


@receiver(pre_social_login)
def handle_pre_social_login(sender, request, sociallogin, **kwargs):
    """Handle pre-social login to store provider info."""
    if request and hasattr(request, 'session') and sociallogin.account:
        request.session['socialaccount_provider'] = sociallogin.account.provider
        request.session.modified = True


