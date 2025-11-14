from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from . import credential_views
from . import internal_views

urlpatterns = [
    # Custom authentication
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('verify-email/', views.verify_email, name='verify-email'),
    path('resend-verification/', views.resend_verification_email, name='resend-verification'),
    
    # User profile
    path('profile/', views.user_profile, name='user-profile'),
    path('profile/update/', views.update_profile, name='update-profile'),
    
    # OAuth
    path('google/', views.GoogleLogin.as_view(), name='google-login'),
    path('github/', views.GitHubLogin.as_view(), name='github-login'),
    path('oauth/config/<str:provider>/', views.oauth_config, name='oauth-config'),
    path('oauth/exchange/', views.oauth_exchange, name='oauth-exchange'),
    path('oauth/session-tokens/', views.oauth_session_tokens, name='oauth-session-tokens'),
    
    # Token refresh
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Credentials - OAuth Apps
    path('credentials/oauth-apps/', credential_views.OAuthAppListCreateView.as_view(), name='oauth-app-list-create'),
    path('credentials/oauth-apps/<int:pk>/', credential_views.OAuthAppDetailView.as_view(), name='oauth-app-detail'),
    path('credentials/oauth-apps/<int:pk>/restore/', credential_views.restore_oauth_app, name='oauth-app-restore'),
    path('credentials/oauth-apps/deleted/', credential_views.list_deleted_oauth_apps, name='oauth-app-deleted-list'),
    
    # Credentials - API Keys
    path('credentials/api-keys/', credential_views.APIKeyListCreateView.as_view(), name='api-key-list-create'),
    path('credentials/api-keys/<int:pk>/', credential_views.APIKeyDetailView.as_view(), name='api-key-detail'),
    path('credentials/api-keys/<int:pk>/show/', credential_views.show_api_key, name='api-key-show'),
    path('credentials/api-keys/<int:pk>/restore/', credential_views.restore_api_key, name='api-key-restore'),
    path('credentials/api-keys/deleted/', credential_views.list_deleted_api_keys, name='api-key-deleted-list'),
    
    # Bulk operations
    path('credentials/bulk-delete/', credential_views.bulk_delete_credentials, name='credentials-bulk-delete'),
    
    # OAuth 2.0 Provider Endpoints (for other platforms to use SVA as OAuth provider)
    path('oauth/authorize/', views.oauth_authorize, name='oauth-authorize'),
    path('oauth/token/', views.oauth_token, name='oauth-token'),
    path('oauth/userinfo/', views.oauth_userinfo, name='oauth-userinfo'),
    path('oauth/revoke/', views.oauth_revoke, name='oauth-revoke'),

    # Internal orchestration endpoints
    path('internal/auth-request-details/', internal_views.auth_request_details, name='internal-auth-request-details'),
    path('internal/consent-complete/', internal_views.consent_complete, name='internal-consent-complete'),
    # Alternative route for frontend compatibility
    path('internal/oauth/requests/<uuid:auth_request_id>/complete/', internal_views.consent_complete, name='internal-oauth-request-complete'),
    
    # OAuth Consent Screen
    path('credentials/consent-screens/', credential_views.list_consent_screens, name='consent-screen-list'),
    path('credentials/oauth-apps/<int:oauth_app_id>/consent-screen/', credential_views.oauth_consent_screen, name='oauth-consent-screen'),
]


