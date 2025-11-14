from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
import secrets
import uuid


class UserManager(BaseUserManager):
    """Custom user manager where email is the unique identifier."""
    
    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular user with the given email and password."""
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a superuser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_email_verified', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model that uses email instead of username."""
    
    email = models.EmailField(unique=True, db_index=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)
    
    # OAuth related fields
    auth_provider = models.CharField(
        max_length=50,
        default='email',
        choices=[
            ('email', 'Email'),
            ('google', 'Google'),
            ('github', 'GitHub'),
        ]
    )
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
    
    def __str__(self):
        return self.email
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip() or self.email.split('@')[0]


class EmailVerificationToken(models.Model):
    """Model to store email verification tokens."""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_tokens')
    token = models.CharField(max_length=64, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Verification token for {self.user.email}"
    
    @classmethod
    def generate_token(cls, user):
        """Generate a new verification token for a user."""
        # Delete old unused tokens for this user
        cls.objects.filter(user=user, is_used=False).delete()
        
        # Generate new token
        token = secrets.token_urlsafe(32)
        expires_at = timezone.now() + timezone.timedelta(days=1)  # Token expires in 24 hours
        
        return cls.objects.create(
            user=user,
            token=token,
            expires_at=expires_at
        )
    
    def is_valid(self):
        """Check if token is valid and not expired."""
        return not self.is_used and timezone.now() < self.expires_at


class OAuthApp(models.Model):
    """Model for user-created OAuth 2.0 applications."""
    
    APP_TYPES = [
        ('web', 'Web application'),
        ('mobile', 'Mobile application'),
        ('desktop', 'Desktop application'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='oauth_apps')
    name = models.CharField(max_length=255)
    app_type = models.CharField(max_length=20, choices=APP_TYPES, default='web')
    client_id = models.CharField(max_length=255, unique=True, db_index=True)
    client_secret = models.CharField(max_length=255)
    redirect_uris = models.TextField(help_text='One URI per line')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'OAuth Application'
        verbose_name_plural = 'OAuth Applications'
    
    def __str__(self):
        return f"{self.name} ({self.user.email})"
    
    @classmethod
    def generate_client_id(cls):
        """Generate a unique client ID."""
        while True:
            client_id = f"app_{secrets.token_urlsafe(32)}"
            if not cls.objects.filter(client_id=client_id).exists():
                return client_id
    
    @classmethod
    def generate_client_secret(cls):
        """Generate a client secret."""
        return secrets.token_urlsafe(48)
    
    def soft_delete(self):
        """Soft delete the app."""
        self.is_deleted = True
        self.is_active = False
        self.deleted_at = timezone.now()
        self.save()
    
    def restore(self):
        """Restore a soft-deleted app."""
        self.is_deleted = False
        self.is_active = True
        self.deleted_at = None
        self.save()


class OAuthConsentScreen(models.Model):
    """Model for OAuth consent screen configuration."""
    
    PUBLISHING_STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('testing', 'Testing'),
        ('published', 'Published'),
    ]
    
    oauth_app = models.OneToOneField(
        OAuthApp, 
        on_delete=models.CASCADE, 
        related_name='consent_screen'
    )
    
    # App Information
    app_name = models.CharField(
        max_length=100, 
        help_text='The name of the application shown to users'
    )
    app_description = models.TextField(
        blank=True,
        max_length=500,
        help_text='Application description shown to users (max 500 characters)'
    )
    app_logo = models.URLField(
        blank=True, 
        help_text='URL to the application logo (must be publicly accessible)'
    )
    support_email = models.EmailField(
        help_text='Support email address for users'
    )
    application_homepage = models.URLField(
        blank=True,
        help_text='Application homepage URL'
    )
    
    # Privacy and Terms
    privacy_policy_url = models.URLField(
        blank=True,
        help_text='Privacy policy URL'
    )
    terms_of_service_url = models.URLField(
        blank=True,
        help_text='Terms of service URL'
    )
    
    # Authorized Domains
    authorized_domains = models.TextField(
        blank=True,
        help_text='Authorized domains (one per line). Users from these domains can access the app.'
    )
    
    # Developer Information
    developer_contact_email = models.EmailField(
        help_text='Developer contact email'
    )
    
    # Scopes with reasons (enhanced scope descriptions)
    # Format: {"scope": {"description": "...", "reason": "..."}}
    scope_reasons = models.JSONField(
        default=dict,
        blank=True,
        help_text='Scope descriptions and reasons (JSON format: {"scope": {"description": "...", "reason": "..."}})'
    )
    
    # Legacy field for backward compatibility
    scope_descriptions = models.JSONField(
        default=dict,
        blank=True,
        help_text='Custom descriptions for scopes (JSON format: {"scope": "description"}) - Legacy field'
    )
    
    # Publishing Status
    publishing_status = models.CharField(
        max_length=20,
        choices=PUBLISHING_STATUS_CHOICES,
        default='draft',
        help_text='Publishing status of the consent screen'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'OAuth Consent Screen'
        verbose_name_plural = 'OAuth Consent Screens'
        ordering = ['-updated_at']
    
    def __str__(self):
        return f"Consent screen for {self.oauth_app.name}"
    
    def get_authorized_domains_list(self):
        """Return authorized domains as a list."""
        if self.authorized_domains:
            return [domain.strip() for domain in self.authorized_domains.split('\n') if domain.strip()]
        return []
    
    def get_scope_info(self, scope):
        """Get description and reason for a scope."""
        if scope in self.scope_reasons:
            return self.scope_reasons[scope]
        # Fallback to legacy scope_descriptions
        if scope in self.scope_descriptions:
            return {
                'description': self.scope_descriptions[scope],
                'reason': ''
            }
        return {'description': '', 'reason': ''}


class APIKey(models.Model):
    """Model for API keys."""
    
    KEY_TYPES = [
        ('server', 'Server key'),
        ('browser', 'Browser key'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=255)
    key_type = models.CharField(max_length=20, choices=KEY_TYPES, default='server')
    api_key = models.CharField(max_length=255, unique=True, db_index=True)
    bound_account = models.CharField(max_length=255, blank=True, help_text='Account or email bound to this key')
    restrictions = models.TextField(blank=True, help_text='API restrictions (JSON format)')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'API Key'
        verbose_name_plural = 'API Keys'
    
    def __str__(self):
        return f"{self.name} ({self.user.email})"
    
    @classmethod
    def generate_api_key(cls):
        """Generate a unique API key."""
        while True:
            api_key = f"sk_{secrets.token_urlsafe(40)}"
            if not cls.objects.filter(api_key=api_key).exists():
                return api_key
    
    def soft_delete(self):
        """Soft delete the API key."""
        self.is_deleted = True
        self.is_active = False
        self.deleted_at = timezone.now()
        self.save()
    
    def restore(self):
        """Restore a soft-deleted API key."""
        self.is_deleted = False
        self.is_active = True
        self.deleted_at = None
        self.save()
    
    def mask_key(self):
        """Return a masked version of the API key for display."""
        if len(self.api_key) > 8:
            return f"{self.api_key[:8]}...{self.api_key[-4:]}"
        return "****"


class OAuthAuthorizationRequest(models.Model):
    """Pending OAuth authorization requests awaiting user consent."""

    STATUS_PENDING = 'pending'
    STATUS_APPROVED = 'approved'
    STATUS_DENIED = 'denied'
    STATUS_EXPIRED = 'expired'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_DENIED, 'Denied'),
        (STATUS_EXPIRED, 'Expired'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    oauth_app = models.ForeignKey(OAuthApp, on_delete=models.CASCADE, related_name='authorization_requests')
    redirect_uri = models.URLField()
    scope = models.TextField(blank=True, help_text='Space-separated list of requested scopes')
    state = models.CharField(max_length=255, blank=True)
    code_challenge = models.CharField(max_length=255, blank=True, help_text='PKCE code challenge')
    code_challenge_method = models.CharField(max_length=10, blank=True, choices=[('S256', 'S256'), ('plain', 'plain')])
    nonce = models.CharField(max_length=255, blank=True)
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    subject = models.CharField(max_length=64, blank=True, help_text='Opaque subject identifier from SVA Core')
    approved_scopes = models.TextField(blank=True, help_text='Space-separated list of approved scopes')
    data_token = models.TextField(blank=True, help_text='Signed data token issued by SVA Core')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'OAuth Authorization Request'
        verbose_name_plural = 'OAuth Authorization Requests'

    def __str__(self):
        return f"Auth request {self.id} for {self.oauth_app.name}"

    @property
    def is_expired(self):
        return timezone.now() >= self.expires_at


class OAuthAuthorizationCode(models.Model):
    """Model for OAuth 2.0 authorization codes."""
    
    code = models.CharField(max_length=255, unique=True, db_index=True)
    oauth_app = models.ForeignKey(OAuthApp, on_delete=models.CASCADE, related_name='authorization_codes')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='oauth_authorization_codes', null=True, blank=True)
    subject = models.CharField(max_length=64, blank=True, help_text='Opaque subject identifier from SVA Core')
    redirect_uri = models.URLField()
    scope = models.TextField(blank=True, help_text='Space-separated list of scopes')
    approved_scopes = models.TextField(blank=True, help_text='Space-separated list of approved scopes')
    code_challenge = models.CharField(max_length=255, blank=True, help_text='PKCE code challenge')
    code_challenge_method = models.CharField(max_length=10, blank=True, choices=[('S256', 'S256'), ('plain', 'plain')])
    data_token = models.TextField(blank=True, help_text='Signed data token issued by SVA Core')
    auth_request = models.OneToOneField(
        OAuthAuthorizationRequest,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='authorization_code'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'OAuth Authorization Code'
        verbose_name_plural = 'OAuth Authorization Codes'
    
    def __str__(self):
        identifier = self.user.email if self.user else self.subject or 'unknown subject'
        return f"Code for {self.oauth_app.name} - {identifier}"
    
    def is_valid(self):
        """Check if authorization code is valid and not expired."""
        return not self.is_used and timezone.now() < self.expires_at
    
    @classmethod
    def generate_code(cls):
        """Generate a unique authorization code."""
        while True:
            code = secrets.token_urlsafe(64)
            if not cls.objects.filter(code=code).exists():
                return code


class OAuthAccessToken(models.Model):
    """Model for OAuth 2.0 access tokens."""
    
    token = models.CharField(max_length=255, unique=True, db_index=True)
    oauth_app = models.ForeignKey(OAuthApp, on_delete=models.CASCADE, related_name='access_tokens')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='oauth_access_tokens', null=True, blank=True)
    subject = models.CharField(max_length=64, blank=True, help_text='Opaque subject identifier from SVA Core')
    authorization_code = models.ForeignKey(
        OAuthAuthorizationCode, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='access_tokens'
    )
    refresh_token = models.ForeignKey(
        'OAuthRefreshToken',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='access_tokens'
    )
    scope = models.TextField(blank=True, help_text='Space-separated list of scopes')
    data_token = models.TextField(blank=True, help_text='Signed data token issued by SVA Core')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_revoked = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'OAuth Access Token'
        verbose_name_plural = 'OAuth Access Tokens'
    
    def __str__(self):
        identifier = self.user.email if self.user else self.subject or 'unknown subject'
        return f"Access token for {self.oauth_app.name} - {identifier}"
    
    def is_valid(self):
        """Check if access token is valid and not expired."""
        return not self.is_revoked and timezone.now() < self.expires_at
    
    @classmethod
    def generate_token(cls):
        """Generate a unique access token."""
        while True:
            token = secrets.token_urlsafe(64)
            if not cls.objects.filter(token=token).exists():
                return token


class OAuthRefreshToken(models.Model):
    """Model for OAuth 2.0 refresh tokens."""
    
    token = models.CharField(max_length=255, unique=True, db_index=True)
    oauth_app = models.ForeignKey(OAuthApp, on_delete=models.CASCADE, related_name='refresh_tokens')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='oauth_refresh_tokens', null=True, blank=True)
    subject = models.CharField(max_length=64, blank=True, help_text='Opaque subject identifier from SVA Core')
    # Note: Access token relationship is handled via refresh_token field in OAuthAccessToken
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True, help_text='None means never expires')
    is_revoked = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'OAuth Refresh Token'
        verbose_name_plural = 'OAuth Refresh Tokens'
    
    def __str__(self):
        identifier = self.user.email if self.user else self.subject or 'unknown subject'
        return f"Refresh token for {self.oauth_app.name} - {identifier}"
    
    def is_valid(self):
        """Check if refresh token is valid and not expired."""
        if self.is_revoked:
            return False
        if self.expires_at:
            return timezone.now() < self.expires_at
        return True
    
    @classmethod
    def generate_token(cls):
        """Generate a unique refresh token."""
        while True:
            token = secrets.token_urlsafe(64)
            if not cls.objects.filter(token=token).exists():
                return token


