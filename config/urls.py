"""
URL configuration for sva-o-auth project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from accounts.oauth_views import GoogleOAuth2LoginView, GitHubOAuth2LoginView
from accounts.oauth_callback_view import google_oauth_callback, github_oauth_callback
from accounts.account_views import CustomSocialSignupView
from .views import HealthCheckView

urlpatterns = [
    # Health check endpoints
    # Primary: /health (standard practice, avoids root path issues)
    path('health', HealthCheckView.as_view(), name='health_check'),
    path('health/', HealthCheckView.as_view(), name='health_check_slash'),
    # Secondary: root path (for Azure App Service default health checks)
    path('', HealthCheckView.as_view(), name='health_check_root'),
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),
    # Override django-allauth OAuth views with custom ones that redirect immediately
    path('accounts/google/login/', GoogleOAuth2LoginView.as_view(), name='google_login'),
    path('accounts/github/login/', GitHubOAuth2LoginView.as_view(), name='github_login'),
    # Override OAuth callback views to redirect to frontend with tokens
    path('accounts/google/login/callback/', google_oauth_callback, name='google_callback'),
    path('accounts/github/login/callback/', github_oauth_callback, name='github_callback'),
    # Override social signup to prevent HTML pages
    path('accounts/social/signup/', CustomSocialSignupView.as_view(), name='socialaccount_signup'),
    # Keep other allauth URLs
    path('accounts/', include('allauth.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)


