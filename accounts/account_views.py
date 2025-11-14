"""
Override django-allauth account views to prevent HTML pages and redirect properly.
"""
from django.http import HttpResponseRedirect
from django.conf import settings
from allauth.account.views import SignupView, LoginView
from allauth.socialaccount.views import SignupView as SocialSignupView


class CustomSocialSignupView(SocialSignupView):
    """Override social signup to auto-complete and redirect."""
    
    def dispatch(self, request, *args, **kwargs):
        # Auto-complete the signup without showing form
        # This is handled by SOCIALACCOUNT_AUTO_SIGNUP = True
        # But we override to ensure no HTML is shown
        response = super().dispatch(request, *args, **kwargs)
        
        # If user is authenticated, redirect to frontend
        if request.user.is_authenticated:
            frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
            return HttpResponseRedirect(f"{frontend_url}/dashboard")
        
        return response

