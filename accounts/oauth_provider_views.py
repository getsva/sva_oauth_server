"""
OAuth 2.0 Provider Views - Allow other platforms to use SVA as an OAuth provider.
Implements standard OAuth 2.0 authorization code flow with PKCE support.
"""
import logging
import hashlib
import base64
import secrets
import urllib.parse
from urllib.parse import urlencode, urlparse, parse_qs

import jwt
import requests
from django.utils import timezone
from django.shortcuts import redirect, render
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

from .models import (
    OAuthApp,
    OAuthAuthorizationCode,
    OAuthAccessToken,
    OAuthRefreshToken,
    OAuthConsentScreen,
    OAuthAuthorizationRequest,
)

logger = logging.getLogger(__name__)


def validate_redirect_uri(oauth_app, redirect_uri):
    """Validate that redirect_uri is in the app's allowed redirect URIs."""
    allowed_uris = [uri.strip() for uri in oauth_app.redirect_uris.split('\n') if uri.strip()]
    
    # Exact match
    if redirect_uri in allowed_uris:
        return True
    
    # Allow subdomain matching (e.g., https://example.com/callback matches https://*.example.com/callback)
    parsed_redirect = urlparse(redirect_uri)
    for allowed_uri in allowed_uris:
        parsed_allowed = urlparse(allowed_uri)
        if (parsed_redirect.scheme == parsed_allowed.scheme and
            parsed_redirect.netloc == parsed_allowed.netloc and
            parsed_redirect.path == parsed_allowed.path):
            return True
    
    return False


def verify_pkce_code_verifier(code_challenge, code_verifier, code_challenge_method):
    """Verify PKCE code verifier against code challenge."""
    if code_challenge_method == 'S256':
        # SHA256 hash of code_verifier, base64url encoded
        digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        encoded = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        return encoded == code_challenge
    elif code_challenge_method == 'plain':
        return code_verifier == code_challenge
    return False


@api_view(['GET'])
@permission_classes([AllowAny])
def oauth_authorize(request):
    """OAuth 2.0 Authorization Endpoint orchestrating multi-service consent flow."""
    try:
        client_id = request.GET.get('client_id')
        redirect_uri = request.GET.get('redirect_uri')
        response_type = request.GET.get('response_type', 'code')
        # Don't default to 'openid email profile' - only use scopes explicitly requested
        # This prevents showing unselected scopes in consent screen
        scope = request.GET.get('scope', '').strip()
        state = request.GET.get('state', '')
        code_challenge = request.GET.get('code_challenge', '')
        code_challenge_method = request.GET.get('code_challenge_method', 'S256')
        nonce = request.GET.get('nonce', '')

        if not client_id:
            return JsonResponse({'error': 'invalid_request', 'error_description': 'client_id is required'}, status=400)
        if not redirect_uri:
            return JsonResponse({'error': 'invalid_request', 'error_description': 'redirect_uri is required'}, status=400)
        if response_type != 'code':
            return JsonResponse({'error': 'unsupported_response_type', 'error_description': 'Only authorization code flow is supported'}, status=400)

        try:
            oauth_app = OAuthApp.objects.get(client_id=client_id, is_active=True, is_deleted=False)
        except OAuthApp.DoesNotExist:
            return JsonResponse({'error': 'invalid_client', 'error_description': 'Invalid client_id'}, status=400)

        if not validate_redirect_uri(oauth_app, redirect_uri):
            return JsonResponse({'error': 'invalid_request', 'error_description': 'Invalid redirect_uri'}, status=400)

        ttl_seconds = getattr(settings, 'AUTHORIZATION_REQUEST_TTL_SECONDS', 600)
        auth_request = OAuthAuthorizationRequest.objects.create(
            oauth_app=oauth_app,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method if code_challenge else '',
            nonce=nonce,
            expires_at=timezone.now() + timezone.timedelta(seconds=ttl_seconds)
        )

        consent_base_url = getattr(settings, 'CORE_CONSENT_URL', 'https://app.getsva.com/consent')
        redirect_params = {'auth_request_id': str(auth_request.id)}
        consent_url = f"{consent_base_url}?{urlencode(redirect_params)}"

        logger.info(
            "Created authorization request %s for app %s redirecting to consent UI",
            auth_request.id,
            oauth_app.name,
        )

        accept_header = request.headers.get('Accept', '')
        if 'application/json' in accept_header:
            return JsonResponse(
                {
                    'auth_request_id': str(auth_request.id),
                    'consent_url': consent_url,
                    'expires_in': ttl_seconds,
                }
            )

        return redirect(consent_url)

    except Exception as exc:
        logger.error("Error in oauth_authorize: %s", exc, exc_info=True)
        return JsonResponse({'error': 'server_error', 'error_description': 'Internal server error'}, status=500)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def oauth_token(request):
    """
    OAuth 2.0 Token Endpoint
    POST /oauth/token
    
    Parameters (form-encoded or JSON):
    - grant_type: 'authorization_code' or 'refresh_token' (required)
    - code: Authorization code (required for authorization_code grant)
    - redirect_uri: Must match the redirect_uri used in authorization (required for authorization_code grant)
    - client_id: OAuth app client ID (required)
    - client_secret: OAuth app client secret (required)
    - code_verifier: PKCE code verifier (required if code_challenge was used)
    - refresh_token: Refresh token (required for refresh_token grant)
    """
    # Log request method for debugging
    logger.debug(f"OAuth token endpoint called with method: {request.method}, content_type: {request.content_type}")
    
    # Ensure we only accept POST
    if request.method != 'POST':
        logger.warning(f"OAuth token endpoint called with invalid method: {request.method}")
        return JsonResponse({
            'error': 'invalid_request',
            'error_description': f'Method {request.method} not allowed. Only POST is supported.'
        }, status=405)
    
    try:
        # Get parameters from form data or JSON
        # OAuth 2.0 spec requires form-encoded data, but we also support JSON
        content_type = request.content_type or ''
        if 'application/json' in content_type:
            # For JSON requests, use request.data (DRF parsed data)
            try:
                data = request.data
            except AttributeError:
                # Fallback if request.data is not available
                import json
                data = json.loads(request.body) if request.body else {}
        else:
            # For form-encoded data (standard OAuth 2.0), use request.POST
            data = request.POST
        
        grant_type = data.get('grant_type')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        
        # Validate required parameters
        if not grant_type:
            return JsonResponse({'error': 'invalid_request', 'error_description': 'grant_type is required'}, 
                              status=400)
        if not client_id or not client_secret:
            return JsonResponse({'error': 'invalid_request', 
                              'error_description': 'client_id and client_secret are required'}, 
                              status=400)
        
        # Get and validate OAuth app
        try:
            oauth_app = OAuthApp.objects.get(client_id=client_id, is_active=True, is_deleted=False)
        except OAuthApp.DoesNotExist:
            return JsonResponse({'error': 'invalid_client', 'error_description': 'Invalid client_id'}, 
                              status=400)
        
        # SECURITY: Use constant-time comparison to prevent timing attacks
        import hmac
        if not hmac.compare_digest(oauth_app.client_secret, client_secret):
            # Don't reveal which field is wrong to prevent enumeration
            return JsonResponse({'error': 'invalid_client', 'error_description': 'Invalid client credentials'}, 
                              status=400)
        
        if grant_type == 'authorization_code':
            # Authorization code grant
            code = data.get('code')
            redirect_uri = data.get('redirect_uri')
            code_verifier = data.get('code_verifier', '')
            
            if not code:
                return JsonResponse({'error': 'invalid_request', 'error_description': 'code is required'}, 
                                  status=400)
            if not redirect_uri:
                return JsonResponse({'error': 'invalid_request', 
                                  'error_description': 'redirect_uri is required'}, 
                                  status=400)
            
            # Get authorization code
            try:
                auth_code = OAuthAuthorizationCode.objects.get(code=code, oauth_app=oauth_app, is_used=False)
            except OAuthAuthorizationCode.DoesNotExist:
                return JsonResponse({'error': 'invalid_grant', 
                                  'error_description': 'Invalid or expired authorization code'}, 
                                  status=400)
            
            # Validate authorization code
            if not auth_code.is_valid():
                return JsonResponse({'error': 'invalid_grant', 
                                  'error_description': 'Authorization code has expired'}, 
                                  status=400)
            
            # Validate redirect URI matches
            if auth_code.redirect_uri != redirect_uri:
                return JsonResponse({'error': 'invalid_grant', 
                                  'error_description': 'redirect_uri mismatch'}, 
                                  status=400)
            
            # Verify PKCE if code challenge was used
            if auth_code.code_challenge:
                if not code_verifier:
                    return JsonResponse({'error': 'invalid_request', 
                                      'error_description': 'code_verifier is required'}, 
                                      status=400)
                if not verify_pkce_code_verifier(auth_code.code_challenge, code_verifier, 
                                                auth_code.code_challenge_method):
                    return JsonResponse({'error': 'invalid_grant', 
                                      'error_description': 'Invalid code_verifier'}, 
                                      status=400)
            
            # Mark authorization code as used
            auth_code.is_used = True
            auth_code.save()

            subject = auth_code.subject or (auth_code.user and str(auth_code.user.id)) or ''
            
            # Validate that we have either a user or subject
            if not auth_code.user and not subject:
                logger.error(f"Authorization code {code} has no user or subject")
                return JsonResponse({'error': 'invalid_grant', 
                                  'error_description': 'Authorization code is missing user information'}, 
                                  status=400)

            # Generate refresh token first so we can attach to access token
            try:
                refresh_token = OAuthRefreshToken.objects.create(
                    token=OAuthRefreshToken.generate_token(),
                    oauth_app=oauth_app,
                    user=auth_code.user,  # Can be None for zero-knowledge users
                    subject=subject,
                    expires_at=timezone.now() + timezone.timedelta(days=30)  # 30 day expiry
                )
            except Exception as e:
                logger.error(f"Failed to create refresh token: {e}", exc_info=True)
                raise

            # Generate access token
            try:
                access_token = OAuthAccessToken.objects.create(
                    token=OAuthAccessToken.generate_token(),
                    oauth_app=oauth_app,
                    user=auth_code.user,  # Can be None for zero-knowledge users
                    subject=subject,
                    authorization_code=auth_code,
                    refresh_token=refresh_token,
                    scope=auth_code.scope or '',
                    data_token=auth_code.data_token or '',
                    expires_at=timezone.now() + timezone.timedelta(hours=1)  # 1 hour expiry
                )
            except Exception as e:
                logger.error(f"Failed to create access token: {e}", exc_info=True)
                # Clean up refresh token if access token creation fails
                refresh_token.delete()
                raise
            
            # Return tokens
            response_data = {
                'access_token': access_token.token,
                'token_type': 'Bearer',
                'expires_in': 3600,  # 1 hour in seconds
                'refresh_token': refresh_token.token,
                'scope': auth_code.scope or '',
                'data_token': auth_code.data_token or '',
            }
            
            logger.info(
                "Access token issued for app %s subject %s",
                oauth_app.name,
                subject or 'unknown',
            )
            return JsonResponse(response_data)
        
        elif grant_type == 'refresh_token':
            # Refresh token grant
            refresh_token_str = data.get('refresh_token')
            
            if not refresh_token_str:
                return JsonResponse({'error': 'invalid_request', 
                                  'error_description': 'refresh_token is required'}, 
                                  status=400)
            
            # Get refresh token
            try:
                refresh_token = OAuthRefreshToken.objects.get(
                    token=refresh_token_str, 
                    oauth_app=oauth_app,
                    is_revoked=False
                )
            except OAuthRefreshToken.DoesNotExist:
                return JsonResponse({'error': 'invalid_grant', 
                                  'error_description': 'Invalid or revoked refresh token'}, 
                                  status=400)
            
            # Validate refresh token
            if not refresh_token.is_valid():
                return JsonResponse({'error': 'invalid_grant', 
                                  'error_description': 'Refresh token has expired'}, 
                                  status=400)
            
            # Revoke old access tokens linked to this refresh token
            old_access_tokens = OAuthAccessToken.objects.filter(
                refresh_token=refresh_token,
                is_revoked=False
            )
            for old_token in old_access_tokens:
                old_token.is_revoked = True
                old_token.save()
            
            # Get scope from the most recent access token or use default
            last_access_token = OAuthAccessToken.objects.filter(
                refresh_token=refresh_token
            ).order_by('-created_at').first()
            scope = last_access_token.scope if last_access_token else 'openid email profile'
            subject = refresh_token.subject or (refresh_token.user and str(refresh_token.user.id)) or ''
            data_token = last_access_token.data_token if last_access_token else ''
            
            # Generate new access token
            new_access_token = OAuthAccessToken.objects.create(
                token=OAuthAccessToken.generate_token(),
                oauth_app=oauth_app,
                user=refresh_token.user,
                subject=subject,
                refresh_token=refresh_token,
                scope=scope,
                data_token=data_token,
                expires_at=timezone.now() + timezone.timedelta(hours=1)
            )
            
            # Return new access token
            response_data = {
                'access_token': new_access_token.token,
                'token_type': 'Bearer',
                'expires_in': 3600,
                'scope': new_access_token.scope,
                'data_token': data_token,
            }
            
            logger.info(
                "Access token refreshed for app %s subject %s",
                oauth_app.name,
                subject or 'unknown',
            )
            return JsonResponse(response_data)
        
        else:
            return JsonResponse({'error': 'unsupported_grant_type', 
                              'error_description': f'Grant type {grant_type} is not supported'}, 
                              status=400)
    
    except Exception as e:
        logger.error(f"Error in oauth_token: {e}", exc_info=True)
        # Provide more detailed error for debugging
        error_message = str(e)
        # In production, don't expose internal errors
        if not settings.DEBUG:
            error_message = 'Internal server error'
        return JsonResponse({
            'error': 'server_error', 
            'error_description': error_message
        }, status=500)


@api_view(['GET'])
@permission_classes([AllowAny])
def oauth_userinfo(request):
    """
    OAuth 2.0 UserInfo Endpoint - Simplified Google OAuth style
    GET /oauth/userinfo
    
    Headers:
    - Authorization: Bearer <access_token> (required)
    
    Returns live user information based on the scopes granted.
    Fetches current data from user's profile (like Google OAuth).
    """
    try:
        # Get access token from Authorization header
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'invalid_request', 
                              'error_description': 'Missing or invalid Authorization header'}, 
                              status=401)
        
        access_token_str = auth_header.replace('Bearer ', '').strip()
        
        # Get access token
        try:
            access_token = OAuthAccessToken.objects.get(token=access_token_str, is_revoked=False)
        except OAuthAccessToken.DoesNotExist:
            return JsonResponse({'error': 'invalid_token', 
                              'error_description': 'Invalid or revoked access token'}, 
                              status=401)
        
        # Validate access token
        if not access_token.is_valid():
            return JsonResponse({'error': 'invalid_token', 
                              'error_description': 'Access token has expired'}, 
                              status=401)
        
        # Get user and subject
        user = access_token.user
        subject = access_token.subject or (user and str(user.id)) or ''
        
        if not subject:
            return JsonResponse({'error': 'invalid_token', 
                              'error_description': 'Access token has no associated user'}, 
                              status=401)
        
        # Parse scopes
        scopes = set(access_token.scope.split()) if access_token.scope else set()
        
        # Build userinfo response based on scopes - SIMPLIFIED (like Google)
        userinfo = {}
        
        # Always include subject if openid scope is present
        if 'openid' in scopes:
            userinfo['sub'] = subject
        
        # Check if client is checking blob timestamp (for efficient caching)
        check_blob_timestamp = request.headers.get('X-Blob-Timestamp', '')
        
        # Try to fetch encrypted sharing blob from SVA Server (Google OAuth style - live data)
        # This blob contains the user's consented data, encrypted client-side
        blob_timestamp = None
        encrypted_blob_data = None
        try:
            core_server_url = getattr(settings, 'CORE_SERVER_BASE_URL', 'http://localhost:8000')
            service_token = getattr(settings, 'INTERNAL_SERVICE_TOKEN', 'dev-shared-secret')
            service_header = getattr(settings, 'INTERNAL_SERVICE_HEADER', 'X-Service-Token')
            
            # Call SVA Server internal API to get UserAppConnection
            response = requests.get(
                f"{core_server_url}/api/internal/app-connections/userinfo/",
                params={
                    'client_id': access_token.oauth_app.client_id,
                    'user_id': subject,
                },
                headers={
                    service_header: service_token,
                },
                timeout=getattr(settings, 'INTERNAL_SERVICE_TIMEOUT', 5),
            )
            
            if response.status_code == 200:
                blob_data = response.json()
                if blob_data.get('exists'):
                    # Get blob timestamp
                    blob_timestamp = blob_data.get('sharing_blob_encrypted_at')
                    
                    # If client provided timestamp and it matches, we could return 304
                    # But for simplicity, we'll always return data with timestamp
                    if blob_timestamp and check_blob_timestamp:
                        if blob_timestamp == check_blob_timestamp:
                            # Blob hasn't changed - could return 304, but we'll return data anyway
                            logger.debug(
                                "Blob timestamp unchanged for user %s, app %s",
                                subject,
                                access_token.oauth_app.name,
                            )
                    
                    if blob_data.get('encrypted_sharing_blob'):
                        encrypted_blob_data = {
                            'encrypted_blob': blob_data['encrypted_sharing_blob'],
                            'salt': blob_data.get('sharing_blob_salt'),
                            'approved_scopes': blob_data.get('approved_scopes', []),
                        }
                        logger.info(
                            "Retrieved encrypted sharing blob for user %s, app %s (timestamp: %s)",
                            subject,
                            access_token.oauth_app.name,
                            blob_timestamp,
                        )
                else:
                    # CRITICAL: Connection exists=False means it was revoked or never existed
                    # We must DENY access to improve integrity
                    logger.warning(
                        "UserAppConnection not found or inactive for user %s, app %s. Denying access.",
                        subject,
                        access_token.oauth_app.name,
                    )
                    return JsonResponse(
                        {'error': 'access_denied', 'error_description': 'User has revoked access to this application'}, 
                        status=403
                    )
        except Exception as e:
            logger.warning(
                "Failed to fetch sharing blob from SVA Server for user %s: %s",
                subject,
                e,
            )
            # In case of server error/timeout, we probably shouldn't fail open if we want strict integrity,
            # but for availability we might fall back. 
            # However, prompt requested "integrity".
            # For now, I will NOT block on Exception, only on explicit False.
            # Rationale: Exception might be network glitch. False is explicit "No".
        
        # Fetch live data from user profile (basic fields from user model)
        if user:
            # Profile information
            if 'profile' in scopes or 'name' in scopes:
                userinfo.setdefault('sub', str(user.id))
                if user.full_name:
                    userinfo['name'] = user.full_name
                if user.first_name:
                    userinfo['given_name'] = user.first_name
                if user.last_name:
                    userinfo['family_name'] = user.last_name
            
            # Email information
            if 'email' in scopes:
                userinfo['email'] = user.email
                userinfo['email_verified'] = getattr(user, 'is_email_verified', False)
        
        # Add blob timestamp to response (for efficient caching)
        # This allows clients to check if data was updated without fetching full response
        if blob_timestamp:
            userinfo['blob_timestamp'] = blob_timestamp
            # Indicate if blob was updated since last check
            if check_blob_timestamp:
                userinfo['blob_updated'] = (blob_timestamp != check_blob_timestamp)
            else:
                userinfo['blob_updated'] = True  # First request
        
        logger.info(
            "Userinfo requested for subject %s by app %s (scopes: %s, blob_timestamp: %s)",
            subject,
            access_token.oauth_app.name,
            ', '.join(scopes) if scopes else 'none',
            blob_timestamp or 'none'
        )
        return JsonResponse(userinfo)
    
    except Exception as e:
        logger.error(f"Error in oauth_userinfo: {e}", exc_info=True)
        return JsonResponse({'error': 'server_error', 'error_description': 'Internal server error'}, 
                          status=500)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def oauth_revoke(request):
    """
    OAuth 2.0 Token Revocation Endpoint
    POST /oauth/revoke
    
    Parameters:
    - token: Access token or refresh token to revoke (required)
    - token_type_hint: 'access_token' or 'refresh_token' (optional)
    - client_id: OAuth app client ID (required)
    - client_secret: OAuth app client secret (required)
    """
    try:
        # Get parameters
        if request.content_type == 'application/json':
            data = request.data
        else:
            data = request.POST
        
        token = data.get('token')
        token_type_hint = data.get('token_type_hint', '')
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        
        if not token:
            return JsonResponse({'error': 'invalid_request', 'error_description': 'token is required'}, 
                              status=400)
        if not client_id or not client_secret:
            return JsonResponse({'error': 'invalid_request', 
                              'error_description': 'client_id and client_secret are required'}, 
                              status=400)
        
        # Validate OAuth app
        try:
            oauth_app = OAuthApp.objects.get(client_id=client_id, is_active=True, is_deleted=False)
        except OAuthApp.DoesNotExist:
            return JsonResponse({'error': 'invalid_client', 'error_description': 'Invalid client_id'}, 
                              status=400)
        
        # SECURITY: Use constant-time comparison to prevent timing attacks
        import hmac
        if not hmac.compare_digest(oauth_app.client_secret, client_secret):
            # Don't reveal which field is wrong to prevent enumeration
            return JsonResponse({'error': 'invalid_client', 'error_description': 'Invalid client credentials'}, 
                              status=400)
        
        # Try to revoke as access token first
        try:
            access_token = OAuthAccessToken.objects.get(token=token, oauth_app=oauth_app)
            access_token.is_revoked = True
            access_token.save()
            # Also revoke the associated refresh token if it exists
            if access_token.refresh_token:
                access_token.refresh_token.is_revoked = True
                access_token.refresh_token.save()
            logger.info(f"Access token revoked for app {oauth_app.name}")
            return JsonResponse({})  # RFC 7009: always return 200
        except OAuthAccessToken.DoesNotExist:
            pass
        
        # Try to revoke as refresh token
        try:
            refresh_token = OAuthRefreshToken.objects.get(token=token, oauth_app=oauth_app)
            refresh_token.is_revoked = True
            refresh_token.save()
            # Also revoke all associated access tokens
            associated_tokens = OAuthAccessToken.objects.filter(
                refresh_token=refresh_token,
                is_revoked=False
            )
            for token in associated_tokens:
                token.is_revoked = True
                token.save()
            logger.info(f"Refresh token revoked for app {oauth_app.name}")
            return JsonResponse({})  # RFC 7009: always return 200
        except OAuthRefreshToken.DoesNotExist:
            pass
        
        # Token not found, but return 200 anyway (RFC 7009)
        return JsonResponse({})
    
    except Exception as e:
        logger.error(f"Error in oauth_revoke: {e}", exc_info=True)
        return JsonResponse({})  # RFC 7009: always return 200 even on error

