"""
Custom adapter for django-allauth to handle OAuth redirects with JWT tokens.
"""
import logging
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from django.shortcuts import redirect
from django.http import HttpResponseRedirect
from rest_framework_simplejwt.tokens import RefreshToken
from allauth.socialaccount.models import SocialAccount
import json
import urllib.parse

logger = logging.getLogger(__name__)


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """Custom adapter to redirect to frontend with JWT tokens after OAuth."""
    
    def pre_social_login(self, request, sociallogin):
        """Called before social login completes."""
        # Store provider in session for later redirect
        if hasattr(request, 'session') and sociallogin.account:
            request.session['socialaccount_provider'] = sociallogin.account.provider
            request.session.modified = True
            logger.debug(f"Stored provider {sociallogin.account.provider} in session")
    
    def save_user(self, request, sociallogin, form=None):
        """Save the user after OAuth authentication."""
        user = super().save_user(request, sociallogin, form)
        # Store provider in session for redirect
        if hasattr(request, 'session') and sociallogin.account:
            request.session['socialaccount_provider'] = sociallogin.account.provider
            request.session.modified = True
        logger.info(f"Saved user {user.id} from OAuth provider {sociallogin.account.provider}")
        return user
    
    def is_open_for_signup(self, request, sociallogin):
        """Always allow signup via OAuth."""
        return True
    
    def populate_user(self, request, sociallogin, data):
        """Populate user data from social account."""
        user = super().populate_user(request, sociallogin, data)
        # Store provider for redirect
        if hasattr(request, 'session') and sociallogin.account:
            request.session['socialaccount_provider'] = sociallogin.account.provider
            request.session.modified = True
        return user
    
    def get_connect_redirect_url(self, request, socialaccount):
        """Called after connecting a social account."""
        return self._get_redirect_url(request, socialaccount.provider)
    
    def get_login_redirect_url(self, request):
        """Called after successful social login to get redirect URL."""
        # Get provider from the request
        provider = None
        try:
            # Try to get from session first (set by signal)
            if hasattr(request, 'session') and 'socialaccount_provider' in request.session:
                provider = request.session.get('socialaccount_provider')
                # Clear it after use
                del request.session['socialaccount_provider']
                request.session.modified = True
                logger.debug(f"Retrieved provider {provider} from session")
            
            # Fallback: try to get from social account
            if not provider and hasattr(request, 'user') and request.user.is_authenticated:
                try:
                    social_account = SocialAccount.objects.filter(user=request.user).order_by('-id').first()
                    if social_account:
                        provider = social_account.provider
                        logger.debug(f"Retrieved provider {provider} from SocialAccount")
                except Exception as e:
                    logger.warning(f"Error getting provider from SocialAccount: {e}")
            
            if provider:
                redirect_url = self._get_redirect_url(request, provider)
                logger.info(f"Redirecting user {request.user.id} to frontend with provider {provider}")
                # Return URL string - Django will handle the redirect
                return redirect_url
        except Exception as e:
            logger.error(f"Error in get_login_redirect_url: {e}", exc_info=True)
        
        # Fallback to default redirect
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
        logger.warning("Using fallback redirect URL")
        return f"{frontend_url}/dashboard"
    
    def authentication_error(self, request, provider_id, error=None, exception=None, extra_context=None):
        """Handle authentication errors."""
        logger.error(f"OAuth authentication error for provider {provider_id}: {error}", exc_info=exception)
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
        return redirect(f"{frontend_url}/login?error=oauth_error")
    
    def _get_redirect_url(self, request, provider):
        """Generate redirect URL with JWT tokens."""
        try:
            user = request.user
            if user and user.is_authenticated:
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
                
                return f"{frontend_url}/auth/callback/{provider}?{token_params}"
        except Exception as e:
            logger.error(f"Error in _get_redirect_url: {e}", exc_info=True)
        
        # Fallback redirect
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
        return f"{frontend_url}/login?error=oauth_failed"

