import logging
import uuid
from urllib.parse import urlencode

import jwt
from django.conf import settings
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import OAuthAuthorizationRequest, OAuthConsentScreen, OAuthAuthorizationCode, OAuthApp

logger = logging.getLogger(__name__)


class ServiceTokenError(Exception):
    """Raised when internal service token validation fails."""


def _require_service_token(request):
    header_name = getattr(settings, 'INTERNAL_SERVICE_HEADER', 'X-Service-Token')
    expected = getattr(settings, 'INTERNAL_SERVICE_TOKEN', None)

    token = request.headers.get(header_name)
    if not expected:
        logger.warning('INTERNAL_SERVICE_TOKEN is not configured; rejecting internal request')
        raise ServiceTokenError('internal service token missing on server')
    if not token or token != expected:
        raise ServiceTokenError('invalid internal service token')


def _build_scope_details(scope_text: str, oauth_app: OAuthApp):
    # Handle None or empty scope_text - only show scopes that were explicitly requested
    if not scope_text or not scope_text.strip():
        return []
    
    # Parse requested scopes from the OAuth request
    scope_values = [scope.strip() for scope in scope_text.split() if scope.strip()]
    
    # If no scopes were requested, return empty list - don't show any blocks
    if not scope_values:
        return []

    default_scope_descriptions = {
        'openid': 'Verify your identity',
        'email': 'Access your email address',
        'profile': 'Access your profile information (name)',
    }

    block_icons = {
        'username': '👤',
        'name': '🆔',
        'bio': '📝',
        'pronoun': '💬',
        'dob': '📅',
        'images': '🖼️',
        'skills': '💻',
        'hobby': '❤️',
        'address': '📍',
        'social': '🔗',
        'email': '📧',
        'phone': '📱',
        'pan_card': '🆔',
        'crypto_wallet': '₿',
        'education': '🎓',
        'employment': '💼',
        'professional_license': '📜',
        'aadhar': '🆔',
        'driving_license': '🚗',
        'voter_id': '🗳️',
        'passport': '🛂',
    }

    block_names = {
        'username': 'Username',
        'name': 'Name',
        'bio': 'Bio',
        'pronoun': 'Pronouns',
        'dob': 'Date of Birth',
        'images': 'Profile Images',
        'skills': 'Skills',
        'hobby': 'Hobbies',
        'address': 'Address',
        'social': 'Social Links',
        'email': 'Verified Email',
        'phone': 'Verified Phone',
        'pan_card': 'PAN Card',
        'crypto_wallet': 'Crypto Wallet',
        'education': 'Education',
        'employment': 'Employment',
        'professional_license': 'Professional License',
        'aadhar': 'Aadhaar Card',
        'driving_license': 'Driving License',
        'voter_id': 'Voter ID',
        'passport': 'Passport',
    }

    consent_screen = None
    try:
        consent_screen = OAuthConsentScreen.objects.get(oauth_app=oauth_app)
    except OAuthConsentScreen.DoesNotExist:
        pass

    scopes_to_show = []
    
    # CRITICAL: Only show scopes that are BOTH configured in the consent screen AND requested in the OAuth request
    # This ensures only selected Identity Blocks & Permissions that were actually requested are shown
    # NEVER show blocks that weren't explicitly requested in the OAuth request
    
    # Convert scope_values to a set for faster lookup
    requested_scopes_set = set(scope_values)
    
    if consent_screen and consent_screen.scope_reasons and len(consent_screen.scope_reasons) > 0:
        # Consent screen is configured - ONLY show scopes that are:
        # 1. In scope_reasons (configured by developer)
        # 2. In requested_scopes_set (explicitly requested in the OAuth request)
        
        for scope_key, scope_data in consent_screen.scope_reasons.items():
            # CRITICAL: Only show if this scope was explicitly requested in the OAuth request
            if scope_key in requested_scopes_set:
                scope_info = {
                    'name': block_names.get(scope_key, scope_key) if scope_key in block_names else scope_key,
                    'description': scope_data.get('description', default_scope_descriptions.get(scope_key, scope_key)),
                    'reason': scope_data.get('reason', ''),
                    'icon': block_icons.get(scope_key),
                    'key': scope_key,
                }
                scopes_to_show.append(scope_info)
        
        # Also check legacy scope_descriptions for any additional configured scopes
        if consent_screen.scope_descriptions:
            for scope in scope_values:
                # Skip if already added from scope_reasons
                if any(s['key'] == scope for s in scopes_to_show):
                    continue
                
                # Only add if it's in scope_descriptions (legacy configuration) AND was requested
                if scope in consent_screen.scope_descriptions:
                    is_block = scope in block_icons
                    scope_info = {
                        'name': block_names.get(scope, scope) if is_block else scope,
                        'description': consent_screen.scope_descriptions[scope],
                        'reason': '',
                        'icon': block_icons.get(scope),
                        'key': scope,
                    }
                    scopes_to_show.append(scope_info)
    elif consent_screen and consent_screen.scope_descriptions and len(consent_screen.scope_descriptions) > 0:
        # Legacy: Only scope_descriptions configured, no scope_reasons
        # Only show scopes that are BOTH in scope_descriptions AND requested
        for scope in scope_values:
            if scope in consent_screen.scope_descriptions:
                is_block = scope in block_icons
                scope_info = {
                    'name': block_names.get(scope, scope) if is_block else scope,
                    'description': consent_screen.scope_descriptions[scope],
                    'reason': '',
                    'icon': block_icons.get(scope),
                    'key': scope,
                }
                scopes_to_show.append(scope_info)
    else:
        # No consent screen configured OR no blocks configured in consent screen
        # CRITICAL: If developer hasn't configured any blocks, show NOTHING
        # Don't show any scopes (not even basic OAuth scopes) until blocks are configured
        # This ensures developers must explicitly configure what they want to request
        # Return empty list - no scopes to show
        pass

    return scopes_to_show


@api_view(['GET'])
@permission_classes([AllowAny])
def auth_request_details(request):
    """Return metadata about a pending authorization request for the consent UI."""
    try:
        _require_service_token(request)
    except ServiceTokenError as exc:
        logger.warning("auth_request_details rejected: %s", exc)
        return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

    auth_request_id = request.query_params.get('auth_request_id') or request.query_params.get('id')
    if not auth_request_id:
        return Response({'detail': 'auth_request_id is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        request_uuid = uuid.UUID(auth_request_id)
    except ValueError:
        return Response({'detail': 'auth_request_id must be a valid UUID'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        auth_request = OAuthAuthorizationRequest.objects.select_related('oauth_app').get(id=request_uuid)
    except OAuthAuthorizationRequest.DoesNotExist:
        return Response({'detail': 'Authorization request not found'}, status=status.HTTP_404_NOT_FOUND)

    if auth_request.is_expired and auth_request.status == OAuthAuthorizationRequest.STATUS_PENDING:
        auth_request.status = OAuthAuthorizationRequest.STATUS_EXPIRED
        auth_request.save(update_fields=['status', 'updated_at'])

    oauth_app = auth_request.oauth_app

    scopes_to_show = _build_scope_details(auth_request.scope, oauth_app)

    # Safely get consent screen data if it exists
    consent_screen = None
    try:
        consent_screen = oauth_app.consent_screen
    except OAuthConsentScreen.DoesNotExist:
        pass

    response_payload = {
        'auth_request_id': str(auth_request.id),
        'status': auth_request.status,
        'expires_at': auth_request.expires_at,
        'requested_scopes': [scope['key'] for scope in scopes_to_show],
        'scope_details': scopes_to_show,
        'state': auth_request.state,
        'redirect_uri': auth_request.redirect_uri,
        'client': {
            'client_id': oauth_app.client_id,
            'name': oauth_app.name,
            'logo': consent_screen.app_logo if consent_screen else '',
            'description': consent_screen.app_description if consent_screen else '',
        },
    }

    return Response(response_payload)


@api_view(['POST'])
@permission_classes([AllowAny])
def consent_complete(request, auth_request_id=None):
    """Mark an authorization request as approved and issue a code."""
    try:
        _require_service_token(request)
    except ServiceTokenError as exc:
        logger.warning("consent_complete rejected: %s", exc)
        return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

    data = request.data or {}

    # Support both URL parameter (from route) and body parameter
    auth_request_id = auth_request_id or data.get('auth_request_id')
    user_id = data.get('user_id')
    approved_scopes = data.get('approved_scopes') or []
    data_token = data.get('data_token')  # Optional - simplified flow like Google OAuth

    if not auth_request_id or not user_id:
        return Response({'detail': 'auth_request_id and user_id are required'}, status=status.HTTP_400_BAD_REQUEST)

    if isinstance(approved_scopes, str):
        approved_scopes = [scope.strip() for scope in approved_scopes.split() if scope.strip()]

    try:
        request_uuid = uuid.UUID(str(auth_request_id))
    except ValueError:
        return Response({'detail': 'auth_request_id must be a valid UUID'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        auth_request = OAuthAuthorizationRequest.objects.select_related('oauth_app').get(id=request_uuid)
    except OAuthAuthorizationRequest.DoesNotExist:
        return Response({'detail': 'Authorization request not found'}, status=status.HTTP_404_NOT_FOUND)

    if auth_request.status != OAuthAuthorizationRequest.STATUS_PENDING:
        return Response({'detail': f'Request is {auth_request.status} and cannot be completed'}, status=status.HTTP_400_BAD_REQUEST)

    if auth_request.is_expired:
        auth_request.status = OAuthAuthorizationRequest.STATUS_EXPIRED
        auth_request.save(update_fields=['status', 'updated_at'])
        return Response({'detail': 'Authorization request has expired'}, status=status.HTTP_400_BAD_REQUEST)

    requested_scopes = [scope for scope in auth_request.scope.split() if scope]
    
    # Get configured scopes from consent screen - these are valid even if not explicitly requested
    configured_scopes = set()
    try:
        consent_screen = auth_request.oauth_app.consent_screen
        if consent_screen and consent_screen.scope_reasons:
            configured_scopes = set(consent_screen.scope_reasons.keys())
        elif consent_screen and consent_screen.scope_descriptions:
            configured_scopes = set(consent_screen.scope_descriptions.keys())
    except OAuthConsentScreen.DoesNotExist:
        pass
    
    # Approved scopes must be a subset of (requested_scopes OR configured_scopes)
    # This allows approving configured blocks even if they weren't explicitly requested
    valid_scopes = set(requested_scopes) | configured_scopes
    
    if approved_scopes and not set(approved_scopes).issubset(valid_scopes):
        return Response({
            'detail': f'approved_scopes must be a subset of requested or configured scopes. Requested: {requested_scopes}, Configured: {list(configured_scopes)}, Approved: {approved_scopes}'
        }, status=status.HTTP_400_BAD_REQUEST)

    # SIMPLIFIED: data_token is optional (like Google OAuth)
    # If provided, validate it. If not, we'll fetch live data from user profile when needed
    decoded_token = None
    if data_token:
        try:
            decoded_token = jwt.decode(
                data_token,
                settings.DATA_TOKEN_SECRET,
                algorithms=[getattr(settings, 'DATA_TOKEN_ALGORITHM', 'HS256')],
                audience=auth_request.oauth_app.client_id,
            )
            # Validate token matches user and request
            if decoded_token.get('sub') != str(user_id):
                return Response({'detail': 'data_token subject mismatch'}, status=status.HTTP_400_BAD_REQUEST)
            if decoded_token.get('auth_request_id') != str(auth_request.id):
                return Response({'detail': 'data_token auth_request_id mismatch'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.ExpiredSignatureError:
            logger.warning('Data token expired for auth request %s', auth_request.id)
            return Response({'detail': 'Data token has expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidAudienceError:
            logger.warning(
                'Data token audience mismatch for auth request %s: expected %s',
                auth_request.id,
                auth_request.oauth_app.client_id,
            )
            return Response({'detail': 'Data token audience mismatch'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.InvalidSignatureError:
            logger.warning(
                'Data token signature invalid for auth request %s (possible secret mismatch)',
                auth_request.id,
            )
            return Response({'detail': 'Invalid data token signature'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.PyJWTError as exc:
            logger.warning('Failed to verify data token for auth request %s: %s', auth_request.id, exc)
            return Response({'detail': 'Invalid data token'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        logger.info('Consent completed without data_token for auth request %s - will use live data', auth_request.id)

    # Use approved scopes if provided, otherwise use all requested scopes
    # If approved_scopes is empty, it means user denied - but we'll still create code with empty scopes
    if approved_scopes:
        approval_scope_text = ' '.join(approved_scopes)
    else:
        # If no approved scopes, use empty string (user denied all)
        approval_scope_text = ''

    authorization_code = OAuthAuthorizationCode.objects.create(
        code=OAuthAuthorizationCode.generate_code(),
        oauth_app=auth_request.oauth_app,
        user=None,
        subject=str(user_id),
        redirect_uri=auth_request.redirect_uri,
        scope=auth_request.scope,
        approved_scopes=approval_scope_text,
        code_challenge=auth_request.code_challenge,
        code_challenge_method=auth_request.code_challenge_method,
        data_token=data_token or '',  # Optional - can be empty for simplified flow
        auth_request=auth_request,
        expires_at=timezone.now() + timezone.timedelta(minutes=10),
    )

    auth_request.status = OAuthAuthorizationRequest.STATUS_APPROVED
    auth_request.subject = str(user_id)
    auth_request.approved_scopes = approval_scope_text
    auth_request.data_token = data_token or ''  # Optional - can be empty
    auth_request.save(update_fields=['status', 'subject', 'approved_scopes', 'data_token', 'updated_at'])

    params = {'code': authorization_code.code}
    if auth_request.state:
        params['state'] = auth_request.state

    redirect_url = f"{auth_request.redirect_uri}?{urlencode(params)}"

    # Debug: Log data_token presence
    data_token_present = bool(data_token)
    data_token_len = len(data_token) if data_token else 0
    logger.info(
        "Authorization request %s approved; code %s issued for app %s (data_token_present: %s, data_token_len: %d, approved_scopes: %s)",
        auth_request.id,
        authorization_code.code,
        auth_request.oauth_app.name,
        data_token_present,
        data_token_len,
        approval_scope_text,
    )
    logger.info(
        "Redirecting to: %s",
        redirect_url,
    )

    return Response(
        {
            'redirect_uri': redirect_url,
            'authorization_code': authorization_code.code,
            'state': auth_request.state,
            'expires_in': 600,
        },
        status=status.HTTP_200_OK,
    )

