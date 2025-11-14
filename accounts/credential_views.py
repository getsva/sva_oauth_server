from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django.utils import timezone
from .models import OAuthApp, APIKey, OAuthConsentScreen
from .serializers import (
    OAuthAppSerializer,
    OAuthAppCreateSerializer,
    OAuthAppCreateResponseSerializer,
    APIKeySerializer,
    APIKeyCreateSerializer,
    OAuthConsentScreenSerializer,
    OAuthConsentScreenCreateUpdateSerializer
)


class NoPagination(PageNumberPagination):
    """Disable pagination for credential endpoints."""
    page_size = None


# OAuth App Views
class OAuthAppListCreateView(generics.ListCreateAPIView):
    """List and create OAuth apps."""
    permission_classes = [IsAuthenticated]
    pagination_class = NoPagination
    
    def get_queryset(self):
        """Return OAuth apps for the current user, excluding deleted ones."""
        return OAuthApp.objects.filter(
            user=self.request.user,
            is_deleted=False
        ).order_by('-created_at')
    
    def get_serializer_class(self):
        """Use different serializers for GET and POST."""
        if self.request.method == 'POST':
            return OAuthAppCreateSerializer
        return OAuthAppSerializer
    
    def create(self, request, *args, **kwargs):
        """Create a new OAuth app."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        oauth_app = serializer.save()
        
        # Return full details including client_secret (only shown once)
        # Use special response serializer that includes client_secret
        response_serializer = OAuthAppCreateResponseSerializer(oauth_app)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class OAuthAppDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete an OAuth app."""
    permission_classes = [IsAuthenticated]
    serializer_class = OAuthAppSerializer
    
    def get_queryset(self):
        """Return OAuth apps for the current user."""
        return OAuthApp.objects.filter(user=self.request.user)
    
    def destroy(self, request, *args, **kwargs):
        """Soft delete the OAuth app."""
        oauth_app = self.get_object()
        oauth_app.soft_delete()
        return Response(
            {'message': 'OAuth app deleted successfully'},
            status=status.HTTP_200_OK
        )
    
    def update(self, request, *args, **kwargs):
        """Update OAuth app."""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def restore_oauth_app(request, pk):
    """Restore a soft-deleted OAuth app."""
    try:
        oauth_app = OAuthApp.objects.get(pk=pk, user=request.user, is_deleted=True)
        oauth_app.restore()
        serializer = OAuthAppSerializer(oauth_app)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except OAuthApp.DoesNotExist:
        return Response(
            {'message': 'OAuth app not found or not deleted'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_deleted_oauth_apps(request):
    """List all deleted OAuth apps for the current user."""
    deleted_apps = OAuthApp.objects.filter(
        user=request.user,
        is_deleted=True
    ).order_by('-deleted_at')
    serializer = OAuthAppSerializer(deleted_apps, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# API Key Views
class APIKeyListCreateView(generics.ListCreateAPIView):
    """List and create API keys."""
    permission_classes = [IsAuthenticated]
    pagination_class = NoPagination
    
    def get_queryset(self):
        """Return API keys for the current user, excluding deleted ones."""
        return APIKey.objects.filter(
            user=self.request.user,
            is_deleted=False
        ).order_by('-created_at')
    
    def get_serializer_class(self):
        """Use different serializers for GET and POST."""
        if self.request.method == 'POST':
            return APIKeyCreateSerializer
        return APIKeySerializer
    
    def create(self, request, *args, **kwargs):
        """Create a new API key."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        api_key = serializer.save()
        
        # Return full details including api_key (only shown once)
        response_serializer = APIKeySerializer(api_key)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class APIKeyDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update, or delete an API key."""
    permission_classes = [IsAuthenticated]
    serializer_class = APIKeySerializer
    
    def get_queryset(self):
        """Return API keys for the current user."""
        return APIKey.objects.filter(user=self.request.user)
    
    def retrieve(self, request, *args, **kwargs):
        """Retrieve API key (masked by default)."""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        # Don't expose full API key in response
        data = serializer.data
        if 'api_key' in data:
            data['api_key'] = instance.mask_key()
        return Response(data)
    
    def destroy(self, request, *args, **kwargs):
        """Soft delete the API key."""
        api_key = self.get_object()
        api_key.soft_delete()
        return Response(
            {'message': 'API key deleted successfully'},
            status=status.HTTP_200_OK
        )
    
    def update(self, request, *args, **kwargs):
        """Update API key."""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def show_api_key(request, pk):
    """Show the full API key (only once after creation)."""
    try:
        api_key = APIKey.objects.get(pk=pk, user=request.user)
        serializer = APIKeySerializer(api_key)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except APIKey.DoesNotExist:
        return Response(
            {'message': 'API key not found'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def restore_api_key(request, pk):
    """Restore a soft-deleted API key."""
    try:
        api_key = APIKey.objects.get(pk=pk, user=request.user, is_deleted=True)
        api_key.restore()
        serializer = APIKeySerializer(api_key)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except APIKey.DoesNotExist:
        return Response(
            {'message': 'API key not found or not deleted'},
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_deleted_api_keys(request):
    """List all deleted API keys for the current user."""
    deleted_keys = APIKey.objects.filter(
        user=request.user,
        is_deleted=True
    ).order_by('-deleted_at')
    serializer = APIKeySerializer(deleted_keys, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def bulk_delete_credentials(request):
    """Bulk delete credentials (OAuth apps or API keys)."""
    credential_type = request.data.get('type')  # 'oauth_app' or 'api_key'
    ids = request.data.get('ids', [])
    
    if not credential_type or not ids:
        return Response(
            {'message': 'Type and ids are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if credential_type == 'oauth_app':
        deleted = OAuthApp.objects.filter(
            id__in=ids,
            user=request.user,
            is_deleted=False
        )
        for app in deleted:
            app.soft_delete()
        return Response(
            {'message': f'{deleted.count()} OAuth app(s) deleted successfully'},
            status=status.HTTP_200_OK
        )
    elif credential_type == 'api_key':
        deleted = APIKey.objects.filter(
            id__in=ids,
            user=request.user,
            is_deleted=False
        )
        for key in deleted:
            key.soft_delete()
        return Response(
            {'message': f'{deleted.count()} API key(s) deleted successfully'},
            status=status.HTTP_200_OK
        )
    else:
        return Response(
            {'message': 'Invalid type. Must be "oauth_app" or "api_key"'},
            status=status.HTTP_400_BAD_REQUEST
        )


# OAuth Consent Screen Views
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_consent_screens(request):
    """List all consent screens for OAuth apps owned by the user."""
    # Get all OAuth apps for the user
    oauth_apps = OAuthApp.objects.filter(
        user=request.user,
        is_deleted=False
    )
    
    # Get consent screens for these apps
    consent_screens = OAuthConsentScreen.objects.filter(
        oauth_app__in=oauth_apps
    ).select_related('oauth_app').order_by('-updated_at')
    
    serializer = OAuthConsentScreenSerializer(consent_screens, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET', 'POST', 'PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def oauth_consent_screen(request, oauth_app_id):
    """Get or create/update consent screen for an OAuth app."""
    try:
        oauth_app = OAuthApp.objects.get(pk=oauth_app_id, user=request.user, is_deleted=False)
    except OAuthApp.DoesNotExist:
        return Response(
            {'message': 'OAuth app not found or you do not have permission to access it'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    if request.method == 'GET':
        try:
            consent_screen = OAuthConsentScreen.objects.get(oauth_app=oauth_app)
            serializer = OAuthConsentScreenSerializer(consent_screen)
            return Response(serializer.data)
        except OAuthConsentScreen.DoesNotExist:
            return Response(
                {'message': 'Consent screen not configured'},
                status=status.HTTP_404_NOT_FOUND
            )
    
    elif request.method in ['POST', 'PUT', 'PATCH']:
        # Create or update consent screen
        consent_screen = None
        try:
            consent_screen = OAuthConsentScreen.objects.get(oauth_app=oauth_app)
            is_update = True
        except OAuthConsentScreen.DoesNotExist:
            is_update = False
        
        # For POST, always create new; for PUT/PATCH, update existing
        if request.method == 'POST' and is_update:
            return Response(
                {'message': 'Consent screen already exists. Use PUT or PATCH to update.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if request.method in ['PUT', 'PATCH'] and not is_update:
            return Response(
                {'message': 'Consent screen not found. Use POST to create.'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = OAuthConsentScreenCreateUpdateSerializer(
            consent_screen if is_update else None,
            data=request.data,
            partial=request.method == 'PATCH'
        )
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            if is_update:
                consent_screen = serializer.save()
            else:
                consent_screen = serializer.save(oauth_app=oauth_app)
            
            response_serializer = OAuthConsentScreenSerializer(consent_screen)
            return Response(response_serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error saving consent screen: {e}", exc_info=True)
            return Response(
                {'message': 'An error occurred while saving the consent screen. Please try again.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

