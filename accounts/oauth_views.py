"""
Custom OAuth views that immediately redirect to OAuth providers without showing HTML.
Industry-standard OAuth 2.0 implementation using django-allauth.
"""
from allauth.socialaccount.providers.oauth2.views import OAuth2LoginView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client


class GoogleOAuth2LoginView(OAuth2LoginView):
    """Custom Google OAuth view that immediately redirects to Google OAuth provider."""
    adapter_class = GoogleOAuth2Adapter
    client_class = OAuth2Client
    
    def dispatch(self, request, *args, **kwargs):
        """Initialize adapter before parent dispatch."""
        # Initialize adapter with request before calling parent
        self.adapter = self.adapter_class(request)
        return super().dispatch(request, *args, **kwargs)


class GitHubOAuth2LoginView(OAuth2LoginView):
    """Custom GitHub OAuth view that immediately redirects to GitHub OAuth provider."""
    adapter_class = GitHubOAuth2Adapter
    client_class = OAuth2Client
    
    def dispatch(self, request, *args, **kwargs):
        """Initialize adapter before parent dispatch."""
        # Initialize adapter with request before calling parent
        self.adapter = self.adapter_class(request)
        return super().dispatch(request, *args, **kwargs)

