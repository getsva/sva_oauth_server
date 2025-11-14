"""
Custom OAuth callback views that redirect to frontend with JWT tokens.
Industry-standard OAuth 2.0 callback handling using django-allauth's adapter pattern.
"""
import logging
from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from allauth.socialaccount.providers.google.views import oauth2_callback as google_oauth2_callback
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import oauth2_callback as github_oauth2_callback
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.models import SocialAccount
import json
import urllib.parse

logger = logging.getLogger(__name__)
User = get_user_model()


def _redirect_with_tokens(request, user, provider):
    """Generate JWT tokens and redirect to frontend."""
    try:
        # Ensure user is authenticated
        if not user or not user.is_authenticated:
            logger.error(f"User not authenticated in _redirect_with_tokens for provider: {provider}")
            frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
            return HttpResponseRedirect(f"{frontend_url}/login?error=oauth_failed")
        
        # Update user auth_provider if needed
        try:
            social_account = SocialAccount.objects.get(user=user, provider=provider)
            if user.auth_provider == 'email':
                user.auth_provider = provider
                user.is_email_verified = True
                user.save()
            elif not user.is_email_verified:
                user.is_email_verified = True
                user.save()
        except SocialAccount.DoesNotExist:
            logger.warning(f"SocialAccount not found for user {user.id} and provider {provider}")
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        tokens = {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }
        
        # Serialize user data manually to avoid circular imports
        user_data = {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'full_name': user.full_name,
            'is_email_verified': user.is_email_verified,
            'auth_provider': user.auth_provider,
            'date_joined': user.date_joined.isoformat() if user.date_joined else None,
            'last_login': user.last_login.isoformat() if user.last_login else None,
        }
        
        # Build redirect URL with tokens
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
        token_params = urllib.parse.urlencode({
            'access_token': tokens['access'],
            'refresh_token': tokens['refresh'],
            'user': urllib.parse.quote(json.dumps(user_data))
        })
        
        redirect_url = f"{frontend_url}/auth/callback/{provider}?{token_params}"
        logger.info(f"Redirecting user {user.id} to frontend after OAuth success with provider: {provider}")
        return HttpResponseRedirect(redirect_url)
    except Exception as e:
        import traceback
        logger.error(f"Error in _redirect_with_tokens: {e}\n{traceback.format_exc()}")
        # Fallback redirect
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
        return HttpResponseRedirect(f"{frontend_url}/login?error=oauth_failed")


def google_oauth_callback(request):
    """Handle Google OAuth callback and redirect to frontend with tokens."""
    try:
        logger.info("Google OAuth callback received")
        
        # Call django-allauth's callback handler
        response = google_oauth2_callback(request, GoogleOAuth2Adapter)
        
        # Check if user is authenticated after OAuth
        if request.user.is_authenticated:
            logger.info(f"User {request.user.id} authenticated via Google OAuth")
            return _redirect_with_tokens(request, request.user, 'google')
        
        # If response is a redirect, check if it's a signup redirect
        if hasattr(response, 'status_code') and response.status_code == 302:
            # Wait a moment for signals to process, then check again
            if request.user.is_authenticated:
                logger.info(f"User {request.user.id} authenticated via Google OAuth (after redirect)")
                return _redirect_with_tokens(request, request.user, 'google')
            
            # Check if there's an error in the response
            location = response.get('Location', '')
            if 'error' in location.lower() or 'denied' in location.lower():
                logger.warning("Google OAuth was denied or had an error")
                frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
                return redirect(f"{frontend_url}/login?error=oauth_denied")
            
            # Otherwise, redirect to frontend with error
            logger.warning("Google OAuth callback did not authenticate user")
            frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
            return redirect(f"{frontend_url}/login?error=oauth_failed")
        
        # Return the response (shouldn't normally happen)
        logger.warning(f"Unexpected response from Google OAuth callback: {type(response)}")
        return response
    except Exception as e:
        import traceback
        logger.error(f"Error in google_oauth_callback: {e}\n{traceback.format_exc()}")
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
        return redirect(f"{frontend_url}/login?error=oauth_error")


def github_oauth_callback(request):
    """Handle GitHub OAuth callback and redirect to frontend with tokens."""
    try:
        logger.info("GitHub OAuth callback received")
        
        # Call django-allauth's callback handler
        response = github_oauth2_callback(request, GitHubOAuth2Adapter)
        
        # Check if user is authenticated after OAuth
        if request.user.is_authenticated:
            logger.info(f"User {request.user.id} authenticated via GitHub OAuth")
            return _redirect_with_tokens(request, request.user, 'github')
        
        # If response is a redirect, check if it's a signup redirect
        if hasattr(response, 'status_code') and response.status_code == 302:
            # Wait a moment for signals to process, then check again
            if request.user.is_authenticated:
                logger.info(f"User {request.user.id} authenticated via GitHub OAuth (after redirect)")
                return _redirect_with_tokens(request, request.user, 'github')
            
            # Check if there's an error in the response
            location = response.get('Location', '')
            if 'error' in location.lower() or 'denied' in location.lower():
                logger.warning("GitHub OAuth was denied or had an error")
                frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
                return redirect(f"{frontend_url}/login?error=oauth_denied")
            
            # Otherwise, redirect to frontend with error
            logger.warning("GitHub OAuth callback did not authenticate user")
            frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
            return redirect(f"{frontend_url}/login?error=oauth_failed")
        
        # Return the response (shouldn't normally happen)
        logger.warning(f"Unexpected response from GitHub OAuth callback: {type(response)}")
        return response
    except Exception as e:
        import traceback
        logger.error(f"Error in github_oauth_callback: {e}\n{traceback.format_exc()}")
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
        return redirect(f"{frontend_url}/login?error=oauth_error")

