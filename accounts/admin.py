from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, EmailVerificationToken, OAuthApp, APIKey,
    OAuthAuthorizationCode, OAuthAccessToken, OAuthRefreshToken,
    OAuthConsentScreen
)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for User model."""
    
    list_display = ('email', 'first_name', 'last_name', 'is_email_verified', 'auth_provider', 'is_active', 'is_staff', 'date_joined')
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'is_email_verified', 'auth_provider', 'date_joined')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_email_verified', 'groups', 'user_permissions')}),
        ('OAuth', {'fields': ('auth_provider',)}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'is_staff', 'is_superuser'),
        }),
    )


@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    """Admin configuration for EmailVerificationToken model."""
    
    list_display = ('user', 'token', 'is_used', 'created_at', 'expires_at')
    list_filter = ('is_used', 'created_at', 'expires_at')
    search_fields = ('user__email', 'token')
    readonly_fields = ('token', 'created_at', 'expires_at')
    ordering = ('-created_at',)


@admin.register(OAuthApp)
class OAuthAppAdmin(admin.ModelAdmin):
    """Admin configuration for OAuthApp model."""
    
    list_display = ('name', 'user', 'app_type', 'client_id', 'is_active', 'is_deleted', 'created_at')
    list_filter = ('app_type', 'is_active', 'is_deleted', 'created_at')
    search_fields = ('name', 'user__email', 'client_id')
    readonly_fields = ('client_id', 'client_secret', 'created_at', 'updated_at')
    ordering = ('-created_at',)
    
    fieldsets = (
        (None, {'fields': ('user', 'name', 'app_type')}),
        ('Credentials', {'fields': ('client_id', 'client_secret')}),
        ('Configuration', {'fields': ('redirect_uris',)}),
        ('Status', {'fields': ('is_active', 'is_deleted', 'deleted_at')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    """Admin configuration for APIKey model."""
    
    list_display = ('name', 'user', 'key_type', 'masked_api_key', 'is_active', 'is_deleted', 'created_at')
    list_filter = ('key_type', 'is_active', 'is_deleted', 'created_at')
    search_fields = ('name', 'user__email', 'api_key')
    readonly_fields = ('api_key', 'created_at', 'updated_at', 'last_used_at')
    ordering = ('-created_at',)
    
    fieldsets = (
        (None, {'fields': ('user', 'name', 'key_type')}),
        ('Credentials', {'fields': ('api_key',)}),
        ('Configuration', {'fields': ('bound_account', 'restrictions')}),
        ('Status', {'fields': ('is_active', 'is_deleted', 'deleted_at', 'last_used_at')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )
    
    def masked_api_key(self, obj):
        """Display masked API key in admin."""
        return obj.mask_key()
    masked_api_key.short_description = 'API Key'


@admin.register(OAuthAuthorizationCode)
class OAuthAuthorizationCodeAdmin(admin.ModelAdmin):
    """Admin configuration for OAuthAuthorizationCode model."""
    
    list_display = ('code', 'oauth_app', 'user', 'is_used', 'created_at', 'expires_at')
    list_filter = ('is_used', 'created_at', 'expires_at', 'oauth_app')
    search_fields = ('code', 'oauth_app__name', 'user__email')
    readonly_fields = ('code', 'created_at', 'expires_at')
    ordering = ('-created_at',)


@admin.register(OAuthAccessToken)
class OAuthAccessTokenAdmin(admin.ModelAdmin):
    """Admin configuration for OAuthAccessToken model."""
    
    list_display = ('token', 'oauth_app', 'user', 'is_revoked', 'created_at', 'expires_at')
    list_filter = ('is_revoked', 'created_at', 'expires_at', 'oauth_app')
    search_fields = ('token', 'oauth_app__name', 'user__email')
    readonly_fields = ('token', 'created_at', 'expires_at')
    ordering = ('-created_at',)


@admin.register(OAuthRefreshToken)
class OAuthRefreshTokenAdmin(admin.ModelAdmin):
    """Admin configuration for OAuthRefreshToken model."""
    
    list_display = ('token', 'oauth_app', 'user', 'is_revoked', 'created_at', 'expires_at')
    list_filter = ('is_revoked', 'created_at', 'expires_at', 'oauth_app')
    search_fields = ('token', 'oauth_app__name', 'user__email')
    readonly_fields = ('token', 'created_at', 'expires_at')
    ordering = ('-created_at',)


@admin.register(OAuthConsentScreen)
class OAuthConsentScreenAdmin(admin.ModelAdmin):
    """Admin configuration for OAuthConsentScreen model."""
    
    list_display = ('oauth_app', 'app_name', 'support_email', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('app_name', 'oauth_app__name', 'support_email', 'developer_contact_email')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-updated_at',)
    
    fieldsets = (
        (None, {'fields': ('oauth_app',)}),
        ('App Information', {'fields': ('app_name', 'app_logo', 'application_homepage')}),
        ('Contact Information', {'fields': ('support_email', 'developer_contact_email')}),
        ('Legal', {'fields': ('privacy_policy_url', 'terms_of_service_url')}),
        ('Configuration', {'fields': ('authorized_domains', 'scope_descriptions')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )


