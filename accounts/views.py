from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.shortcuts import redirect
from django.conf import settings
from django.utils import timezone
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.github.views import GitHubOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.models import SocialAccount, SocialApp
from allauth.socialaccount.helpers import complete_social_login
from allauth.socialaccount import app_settings
import requests
import json
import urllib.parse
from .serializers import (
    UserSerializer,
    RegisterSerializer,
    LoginSerializer,
    EmailVerificationSerializer,
    ResendVerificationEmailSerializer
)
from .oauth_provider_views import (
    oauth_authorize,
    oauth_token,
    oauth_userinfo,
    oauth_revoke
)

User = get_user_model()


def get_tokens_for_user(user):
    """Generate JWT tokens for user."""
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    """Register a new user."""
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        user_data = UserSerializer(user).data
        return Response({
            'message': 'Registration successful. Please check your email to verify your account.',
            'user': user_data
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    """Login user and return JWT tokens."""
    serializer = LoginSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user = serializer.validated_data['user']
        tokens = get_tokens_for_user(user)
        user_data = UserSerializer(user).data
        return Response({
            'message': 'Login successful',
            'user': user_data,
            'tokens': tokens
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_email(request):
    """Verify user email using token."""
    serializer = EmailVerificationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.verify_email()
        tokens = get_tokens_for_user(user)
        user_data = UserSerializer(user).data
        return Response({
            'message': 'Email verified successfully',
            'user': user_data,
            'tokens': tokens
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def resend_verification_email(request):
    """Resend verification email."""
    serializer = ResendVerificationEmailSerializer(data=request.data)
    if serializer.is_valid():
        serializer.send_verification_email()
        return Response({
            'message': 'Verification email sent successfully. Please check your inbox.'
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    """Get current user profile."""
    serializer = UserSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_profile(request):
    """Update user profile."""
    serializer = UserSerializer(request.user, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response({
            'message': 'Profile updated successfully',
            'user': serializer.data
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Google OAuth
class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    client_class = OAuth2Client
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Get user from the authenticated request
            try:
                user = request.user
                
                if user and not isinstance(user, AnonymousUser):
                    # Update auth_provider if needed
                    if user.auth_provider == 'email':
                        user.auth_provider = 'google'
                    user.is_email_verified = True  # OAuth providers already verify email
                    user.save()
                    
                    # Generate JWT tokens
                    tokens = get_tokens_for_user(user)
                    user_data = UserSerializer(user).data
                    
                    # SECURITY: Don't pass tokens in URL - use session or POST redirect
                    # Store tokens in session temporarily for frontend to retrieve
                    request.session['oauth_tokens'] = {
                        'access': tokens['access'],
                        'refresh': tokens['refresh'],
                        'user': user_data
                    }
                    request.session['oauth_tokens_expires'] = timezone.now().timestamp() + 60  # 60 seconds
                    # Redirect to frontend callback without tokens in URL
                    frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
                    return redirect(f"{frontend_url}/auth/callback/google?session=true")
            except Exception as e:
                # SECURITY: Don't expose internal errors to users
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Error in GoogleLogin: {e}", exc_info=True)
                # Return generic error to user
                frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
                return redirect(f"{frontend_url}/login?error=oauth_error")
        
        return response


# GitHub OAuth
class GitHubLogin(SocialLoginView):
    adapter_class = GitHubOAuth2Adapter
    client_class = OAuth2Client
    
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Get user from the authenticated request
            try:
                user = request.user
                
                if user and not isinstance(user, AnonymousUser):
                    # Update auth_provider if needed
                    if user.auth_provider == 'email':
                        user.auth_provider = 'github'
                    user.is_email_verified = True  # OAuth providers already verify email
                    user.save()
                    
                    # Generate JWT tokens
                    tokens = get_tokens_for_user(user)
                    user_data = UserSerializer(user).data
                    
                    # SECURITY: Don't pass tokens in URL - use session or POST redirect
                    # Store tokens in session temporarily for frontend to retrieve
                    request.session['oauth_tokens'] = {
                        'access': tokens['access'],
                        'refresh': tokens['refresh'],
                        'user': user_data
                    }
                    request.session['oauth_tokens_expires'] = timezone.now().timestamp() + 60  # 60 seconds
                    # Redirect to frontend callback without tokens in URL
                    frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
                    return redirect(f"{frontend_url}/auth/callback/github?session=true")
            except Exception as e:
                # SECURITY: Don't expose internal errors to users
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Error in GitHubLogin: {e}", exc_info=True)
                # Return generic error to user
                frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
                return redirect(f"{frontend_url}/login?error=oauth_error")
        
        return response


@api_view(['POST'])
@permission_classes([AllowAny])
def oauth_exchange(request):
    """
    Exchange OAuth authorization code for tokens.
    This endpoint is called by the frontend after OAuth provider redirects back.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    provider = request.data.get('provider')
    code = request.data.get('code')
    redirect_uri = request.data.get('redirect_uri')
    
    # Normalize redirect_uri - remove trailing slash to ensure exact match
    if redirect_uri:
        redirect_uri = redirect_uri.rstrip('/')
    
    logger.info(f"OAuth exchange request: provider={provider}, redirect_uri={redirect_uri}")
    
    if not provider or not code or not redirect_uri:
        logger.warning(f"Missing required parameters: provider={provider}, code={'present' if code else 'missing'}, redirect_uri={redirect_uri}")
        return Response({
            'message': 'Missing required parameters: provider, code, redirect_uri'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if provider not in ['google', 'github']:
        logger.warning(f"Invalid provider: {provider}")
        return Response({
            'message': f'Invalid provider: {provider}. Must be "google" or "github".'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Get the social app for the provider
        site = request.get_host()
        try:
            social_app = SocialApp.objects.get(provider=provider)
        except SocialApp.DoesNotExist:
            return Response({
                'message': f'OAuth app for {provider} is not configured.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Choose the adapter based on provider
        if provider == 'google':
            adapter = GoogleOAuth2Adapter(request)
            # Get scope from settings or use default
            scope = getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {}).get('google', {}).get('SCOPE', ['profile', 'email'])
        else:  # github
            adapter = GitHubOAuth2Adapter(request)
            # Get scope from settings or use default
            scope = getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {}).get('github', {}).get('SCOPE', ['user:email'])
        
        # Convert scope list to string if needed (for logging, not used in manual exchange)
        if isinstance(scope, list):
            scope = adapter.scope_delimiter.join(scope)
        
        # Exchange code for access token
        # Use manual exchange for frontend-initiated flow to avoid PKCE and OAuth2Client issues
        # This gives us full control over the token exchange process
        token_data = {
            'code': code,
            'client_id': social_app.client_id,
            'client_secret': social_app.secret,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
        }
        
        logger.info(f"Exchanging token for {provider} with redirect_uri: {redirect_uri}")
        logger.info(f"Token URL: {adapter.access_token_url}, Client ID: {social_app.client_id[:10]}...")
        
        # Both Google and GitHub use form-encoded data for token exchange
        # Don't set Content-Type header - requests library will set it automatically with data parameter
        token_response = requests.post(adapter.access_token_url, data=token_data)
        
        if not token_response.ok:
            error_detail = token_response.text
            try:
                error_json = token_response.json()
                error_description = error_json.get('error_description', error_json.get('error', 'Unknown error'))
            except:
                error_description = error_detail
            
            logger.error(f"Token exchange failed: {token_response.status_code} - {error_detail}")
            logger.error(f"Request data (without secret): code={code[:20] if code else 'None'}..., redirect_uri={redirect_uri}, client_id={social_app.client_id[:10]}...")
            
            # Provide helpful error message for common issues
            if 'invalid_grant' in error_detail.lower():
                # Check if it's a redirect_uri mismatch
                if 'redirect_uri' in error_detail.lower() or 'redirect' in error_detail.lower():
                    error_msg = f'Redirect URI mismatch. The redirect URI "{redirect_uri}" must match exactly in {provider} OAuth settings. Please check your {provider} OAuth app configuration.'
                else:
                    error_msg = f'Authorization code expired or already used. Please try logging in again. If this persists, check that the redirect URI "{redirect_uri}" matches exactly in {provider} OAuth settings.'
            else:
                error_msg = f'Failed to exchange authorization code with {provider}.'
            
            return Response({
                'message': error_msg,
                'detail': error_description
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Both GitHub and Google return JSON responses now
        try:
            token_json = token_response.json()
            logger.info(f"{provider} token response keys: {list(token_json.keys())}")
            logger.info(f"{provider} token response (sanitized): { {k: '***' if 'token' in k.lower() or 'secret' in k.lower() else v for k, v in token_json.items()} }")
            
            access_token = token_json.get('access_token')
            
            # Handle case where access_token might be nested
            if isinstance(access_token, dict):
                access_token = access_token.get('access_token') or access_token.get('token')
            
            if not access_token:
                logger.error(f"No access_token in {provider} response: {token_json}")
                return Response({
                    'message': f'Failed to get access token from {provider}.',
                    'detail': str(token_json)
                }, status=status.HTTP_400_BAD_REQUEST)
        except ValueError:
            # Fallback: try parsing as form-encoded (for older GitHub API)
            logger.warning(f"{provider} response is not JSON, trying form-encoded parsing")
            token_text = token_response.text
            from urllib.parse import parse_qs
            token_params = parse_qs(token_text)
            access_token = token_params.get('access_token', [None])[0]
            
            if not access_token:
                logger.error(f"No access_token in {provider} response: {token_text[:200]}")
                return Response({
                    'message': f'Failed to get access token from {provider}.',
                    'detail': 'No access_token in response'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Ensure access_token is a string
        if not isinstance(access_token, str):
            logger.warning(f"Access token is not a string: {type(access_token)}, value: {access_token}")
            # If it's a dict, try to extract the token
            if isinstance(access_token, dict):
                access_token = access_token.get('access_token') or access_token.get('token')
            if not isinstance(access_token, str):
                access_token = str(access_token)
            if not access_token or access_token == 'None' or access_token.startswith('{'):
                logger.error(f"Access token is invalid: {access_token}")
                return Response({
                    'message': f'Invalid access token format from {provider}.',
                    'detail': 'Access token is not in expected format'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"Successfully obtained access token for {provider} (length: {len(access_token)})")
        
        # Get user info from provider
        if provider == 'google':
            # Get user info from Google
            user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
            headers = {'Authorization': f'Bearer {access_token}'}
            user_info_response = requests.get(user_info_url, headers=headers)
            user_info_response.raise_for_status()
            user_info = user_info_response.json()
            
            email = user_info.get('email')
            first_name = user_info.get('given_name', '')
            last_name = user_info.get('family_name', '')
            full_name = user_info.get('name', '')
            
        else:  # github
            # Get user info from GitHub
            user_info_url = 'https://api.github.com/user'
            # Safely get token preview for logging
            if isinstance(access_token, str) and len(access_token) > 20:
                token_preview = access_token[:20] + '...'
            else:
                token_preview = str(access_token)[:20] + '...' if access_token else 'None'
            logger.info(f"Fetching GitHub user info with token: {token_preview}")
            headers = {'Authorization': f'Bearer {access_token}'}  # GitHub API v3+ uses Bearer
            user_info_response = requests.get(user_info_url, headers=headers)
            
            if not user_info_response.ok:
                logger.error(f"GitHub user info failed: {user_info_response.status_code} - {user_info_response.text}")
                # Try with token format as fallback (older GitHub API)
                headers = {'Authorization': f'token {access_token}'}
                user_info_response = requests.get(user_info_url, headers=headers)
            
            user_info_response.raise_for_status()
            user_info = user_info_response.json()
            
            email = user_info.get('email')
            if not email:
                # Try to get email from GitHub emails endpoint
                emails_url = 'https://api.github.com/user/emails'
                emails_response = requests.get(emails_url, headers=headers)
                if emails_response.status_code == 200:
                    emails = emails_response.json()
                    primary_email = next((e for e in emails if e.get('primary')), emails[0] if emails else None)
                    email = primary_email.get('email') if primary_email else None
            
            full_name = user_info.get('name', '')
            name_parts = full_name.split(' ', 1) if full_name else ['', '']
            first_name = name_parts[0] if name_parts else ''
            last_name = name_parts[1] if len(name_parts) > 1 else ''
        
        if not email:
            return Response({
                'message': 'Could not retrieve email from OAuth provider.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get or create user
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'first_name': first_name,
                'last_name': last_name,
                'auth_provider': provider,
                'is_email_verified': True,
            }
        )
        
        # Update user if not created
        if not created:
            if user.auth_provider == 'email':
                user.auth_provider = provider
            user.is_email_verified = True
            if not user.first_name and first_name:
                user.first_name = first_name
            if not user.last_name and last_name:
                user.last_name = last_name
            user.save()
        
        # Create or update social account
        uid = str(user_info.get('id', '')) if provider == 'github' else str(user_info.get('sub', ''))
        social_account, _ = SocialAccount.objects.get_or_create(
            user=user,
            provider=provider,
            defaults={'uid': uid}
        )
        if not social_account.uid:
            social_account.uid = uid
            social_account.save()
        
        # Generate JWT tokens
        tokens = get_tokens_for_user(user)
        user_data = UserSerializer(user).data
        
        return Response({
            'access': tokens['access'],
            'refresh': tokens['refresh'],
            'user': user_data
        }, status=status.HTTP_200_OK)
        
    except requests.RequestException as e:
        logger.error(f"Request exception in oauth_exchange: {e}", exc_info=True)
        return Response({
            'message': f'Failed to communicate with {provider} OAuth provider.',
            'detail': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        # SECURITY: Don't expose internal errors to users
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in oauth_exchange: {e}", exc_info=True)
        return Response({
            'message': 'An error occurred during OAuth exchange. Please try again.',
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def oauth_session_tokens(request):
    """
    Retrieve OAuth tokens from session (for OAuth callback flow).
    Tokens are stored in session temporarily to avoid passing them in URL.
    """
    import time
    from django.utils import timezone
    
    # Check if tokens exist in session and haven't expired
    tokens = request.session.get('oauth_tokens')
    expires = request.session.get('oauth_tokens_expires', 0)
    
    if not tokens or time.time() > expires:
        # Clean up expired session data
        if 'oauth_tokens' in request.session:
            del request.session['oauth_tokens']
        if 'oauth_tokens_expires' in request.session:
            del request.session['oauth_tokens_expires']
        return Response({
            'message': 'OAuth tokens not found or expired. Please try logging in again.'
        }, status=status.HTTP_404_NOT_FOUND)
    
    # Remove tokens from session after retrieval (one-time use)
    del request.session['oauth_tokens']
    del request.session['oauth_tokens_expires']
    
    return Response(tokens, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def oauth_config(request, provider):
    """
    Get OAuth configuration (client ID) for frontend.
    This allows frontend to redirect directly to OAuth providers.
    """
    if provider not in ['google', 'github']:
        return Response({
            'message': f'Invalid provider: {provider}. Must be "google" or "github".'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        social_app = SocialApp.objects.get(provider=provider)
        return Response({
            'client_id': social_app.client_id,
            'provider': provider
        }, status=status.HTTP_200_OK)
    except SocialApp.DoesNotExist:
        return Response({
            'message': f'OAuth app for {provider} is not configured.'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([AllowAny])
def oauth_callback_handler(request):
    """
    Handle OAuth callback from django-allauth.
    This view is called after successful OAuth authentication.
    It retrieves the authenticated user and redirects to frontend with tokens.
    """
    try:
        # Get the authenticated user from the session
        # django-allauth stores the user in the session after OAuth
        user = request.user
        
        if user and not isinstance(user, AnonymousUser):
            # Update auth_provider based on the social account
            try:
                social_account = SocialAccount.objects.get(user=user)
                provider = social_account.provider
                
                if provider == 'google' and user.auth_provider == 'email':
                    user.auth_provider = 'google'
                elif provider == 'github' and user.auth_provider == 'email':
                    user.auth_provider = 'github'
                
                user.is_email_verified = True
                user.save()
            except SocialAccount.DoesNotExist:
                pass
            
            # Generate JWT tokens
            tokens = get_tokens_for_user(user)
            user_data = UserSerializer(user).data
            
            # Redirect to frontend with tokens
            frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
            provider = request.GET.get('provider', 'google')
            
            token_params = urllib.parse.urlencode({
                'access_token': tokens['access'],
                'refresh_token': tokens['refresh'],
                'user': urllib.parse.quote(json.dumps(user_data))
            })
            
            return redirect(f"{frontend_url}/auth/callback/{provider}?{token_params}")
        else:
            # User not authenticated, redirect to login with error
            frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
            return redirect(f"{frontend_url}/login?error=oauth_failed")
            
    except Exception as e:
        # SECURITY: Don't expose internal errors to users
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in oauth_callback_handler: {e}", exc_info=True)
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:8081')
        return redirect(f"{frontend_url}/login?error=oauth_error")

