from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from .models import User, EmailVerificationToken, OAuthApp, APIKey, OAuthConsentScreen
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
import json


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""
    
    full_name = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'full_name', 'is_email_verified', 
                  'auth_provider', 'date_joined', 'last_login')
        read_only_fields = ('id', 'is_email_verified', 'date_joined', 'last_login')


class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True, label='Confirm Password')
    
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'password', 'password2')
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            is_email_verified=False,
            auth_provider='email'
        )
        
        # Generate and send verification email
        token = EmailVerificationToken.generate_token(user)
        self.send_verification_email(user, token)
        
        return user
    
    def send_verification_email(self, user, token):
        """Send email verification email."""
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token.token}"
        
        subject = 'Verify your email address'
        message = f"""
        Hello {user.full_name},
        
        Thank you for signing up! Please verify your email address by clicking the link below:
        
        {verification_url}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, please ignore this email.
        
        Best regards,
        SVA OAuth Team
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )


class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            
            if not user:
                raise serializers.ValidationError('Invalid email or password.')
            
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled.')
            
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Must include "email" and "password".')


class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for email verification."""
    
    token = serializers.CharField(required=True)
    
    def validate_token(self, value):
        try:
            token_obj = EmailVerificationToken.objects.get(token=value)
        except EmailVerificationToken.DoesNotExist:
            raise serializers.ValidationError('Invalid verification token.')
        
        if token_obj.is_used:
            raise serializers.ValidationError('This verification token has already been used.')
        
        if not token_obj.is_valid():
            raise serializers.ValidationError('This verification token has expired.')
        
        return value
    
    def verify_email(self):
        """Verify the email using the token."""
        token = self.validated_data['token']
        token_obj = EmailVerificationToken.objects.get(token=token)
        user = token_obj.user
        
        user.is_email_verified = True
        user.save()
        
        token_obj.is_used = True
        token_obj.save()
        
        return user


class ResendVerificationEmailSerializer(serializers.Serializer):
    """Serializer for resending verification email."""
    
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError('No account found with this email address.')
        
        if user.is_email_verified:
            raise serializers.ValidationError('This email is already verified.')
        
        return value
    
    def send_verification_email(self):
        """Send verification email."""
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        
        # Generate new token
        token = EmailVerificationToken.generate_token(user)
        
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token.token}"
        
        subject = 'Verify your email address'
        message = f"""
        Hello {user.full_name},
        
        You requested a new verification email. Please verify your email address by clicking the link below:
        
        {verification_url}
        
        This link will expire in 24 hours.
        
        If you didn't request this, please ignore this email.
        
        Best regards,
        SVA OAuth Team
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        
        return user


class OAuthAppSerializer(serializers.ModelSerializer):
    """Serializer for OAuthApp model."""
    
    client_secret = serializers.CharField(write_only=True, required=False)
    masked_client_secret = serializers.SerializerMethodField()
    redirect_uris_list = serializers.SerializerMethodField()
    
    class Meta:
        model = OAuthApp
        fields = ('id', 'name', 'app_type', 'client_id', 'client_secret', 
                  'masked_client_secret', 'redirect_uris', 'redirect_uris_list',
                  'created_at', 'updated_at', 'is_active', 'is_deleted')
        read_only_fields = ('id', 'client_id', 'created_at', 'updated_at', 'is_deleted')
    
    def get_masked_client_secret(self, obj):
        """Return masked client secret for display."""
        if obj.client_secret:
            if len(obj.client_secret) > 8:
                return f"{obj.client_secret[:8]}...{obj.client_secret[-4:]}"
            return "****"
        return None
    
    def get_redirect_uris_list(self, obj):
        """Return redirect URIs as a list."""
        if obj.redirect_uris:
            return [uri.strip() for uri in obj.redirect_uris.split('\n') if uri.strip()]
        return []
    
    def create(self, validated_data):
        """Create a new OAuth app with generated credentials."""
        user = self.context['request'].user
        validated_data['user'] = user
        validated_data['client_id'] = OAuthApp.generate_client_id()
        
        # Only set client_secret if provided, otherwise generate one
        if 'client_secret' not in validated_data or not validated_data['client_secret']:
            validated_data['client_secret'] = OAuthApp.generate_client_secret()
        
        return super().create(validated_data)


class OAuthAppCreateResponseSerializer(serializers.ModelSerializer):
    """Serializer for OAuthApp creation response - includes client_secret."""
    
    masked_client_secret = serializers.SerializerMethodField()
    redirect_uris_list = serializers.SerializerMethodField()
    
    class Meta:
        model = OAuthApp
        fields = ('id', 'name', 'app_type', 'client_id', 'client_secret', 
                  'masked_client_secret', 'redirect_uris', 'redirect_uris_list',
                  'created_at', 'updated_at', 'is_active', 'is_deleted')
        read_only_fields = ('id', 'client_id', 'client_secret', 'created_at', 'updated_at', 'is_deleted')
    
    def get_masked_client_secret(self, obj):
        """Return masked client secret for display."""
        if obj.client_secret:
            if len(obj.client_secret) > 8:
                return f"{obj.client_secret[:8]}...{obj.client_secret[-4:]}"
            return "****"
        return None
    
    def get_redirect_uris_list(self, obj):
        """Return redirect URIs as a list."""
        if obj.redirect_uris:
            return [uri.strip() for uri in obj.redirect_uris.split('\n') if uri.strip()]
        return []


class OAuthAppCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating OAuthApp (without exposing client_secret in response)."""
    
    redirect_uris_list = serializers.ListField(
        child=serializers.URLField(),
        required=False,
        allow_empty=False,
        help_text='List of redirect URIs'
    )
    
    class Meta:
        model = OAuthApp
        fields = ('name', 'app_type', 'redirect_uris', 'redirect_uris_list')
        extra_kwargs = {
            'redirect_uris': {'required': False, 'allow_blank': True}
        }
    
    def validate(self, attrs):
        """Convert redirect_uris_list to redirect_uris string."""
        redirect_uris_list = attrs.pop('redirect_uris_list', None)
        redirect_uris = attrs.get('redirect_uris', '')
        
        # If redirect_uris_list is provided, use it
        if redirect_uris_list is not None:
            if not redirect_uris_list:
                raise serializers.ValidationError({
                    'redirect_uris_list': 'At least one redirect URI is required.'
                })
            attrs['redirect_uris'] = '\n'.join(redirect_uris_list)
        # If neither is provided, raise error
        elif not redirect_uris:
            raise serializers.ValidationError({
                'redirect_uris': 'At least one redirect URI is required. Provide either redirect_uris or redirect_uris_list.'
            })
        
        return attrs
    
    def create(self, validated_data):
        """Create a new OAuth app with generated credentials."""
        user = self.context['request'].user
        oauth_app = OAuthApp.objects.create(
            user=user,
            name=validated_data['name'],
            app_type=validated_data.get('app_type', 'web'),
            redirect_uris=validated_data.get('redirect_uris', ''),
            client_id=OAuthApp.generate_client_id(),
            client_secret=OAuthApp.generate_client_secret(),
        )
        return oauth_app


class APIKeySerializer(serializers.ModelSerializer):
    """Serializer for APIKey model."""
    
    masked_api_key = serializers.SerializerMethodField()
    restrictions_dict = serializers.SerializerMethodField()
    
    class Meta:
        model = APIKey
        fields = ('id', 'name', 'key_type', 'api_key', 'masked_api_key', 
                  'bound_account', 'restrictions', 'restrictions_dict',
                  'created_at', 'updated_at', 'last_used_at', 'is_active', 'is_deleted')
        read_only_fields = ('id', 'api_key', 'created_at', 'updated_at', 
                          'last_used_at', 'is_deleted')
    
    def get_masked_api_key(self, obj):
        """Return masked API key for display."""
        return obj.mask_key()
    
    def get_restrictions_dict(self, obj):
        """Return restrictions as a dictionary."""
        if obj.restrictions:
            try:
                return json.loads(obj.restrictions)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def create(self, validated_data):
        """Create a new API key with generated key."""
        user = self.context['request'].user
        validated_data['user'] = user
        validated_data['api_key'] = APIKey.generate_api_key()
        return super().create(validated_data)


class APIKeyCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating APIKey."""
    
    restrictions_dict = serializers.DictField(
        required=False,
        help_text='API restrictions as JSON object'
    )
    
    class Meta:
        model = APIKey
        fields = ('name', 'key_type', 'bound_account', 'restrictions', 'restrictions_dict')
    
    def validate(self, attrs):
        """Convert restrictions_dict to restrictions string."""
        if 'restrictions_dict' in attrs:
            restrictions_dict = attrs.pop('restrictions_dict')
            attrs['restrictions'] = json.dumps(restrictions_dict)
        return attrs
    
    def create(self, validated_data):
        """Create a new API key with generated key."""
        user = self.context['request'].user
        api_key = APIKey.objects.create(
            user=user,
            name=validated_data['name'],
            key_type=validated_data.get('key_type', 'server'),
            bound_account=validated_data.get('bound_account', ''),
            restrictions=validated_data.get('restrictions', ''),
            api_key=APIKey.generate_api_key(),
        )
        return api_key


class OAuthConsentScreenSerializer(serializers.ModelSerializer):
    """Serializer for OAuthConsentScreen model."""
    
    authorized_domains_list = serializers.SerializerMethodField()
    oauth_app_name = serializers.CharField(source='oauth_app.name', read_only=True)
    oauth_app_client_id = serializers.CharField(source='oauth_app.client_id', read_only=True)
    
    class Meta:
        model = OAuthConsentScreen
        fields = (
            'id', 'oauth_app', 'oauth_app_name', 'oauth_app_client_id',
            'app_name', 'app_description', 'app_logo', 'support_email',
            'application_homepage', 'privacy_policy_url', 'terms_of_service_url',
            'authorized_domains', 'authorized_domains_list', 'developer_contact_email',
            'scope_descriptions', 'scope_reasons', 'publishing_status',
            'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_authorized_domains_list(self, obj):
        """Return authorized domains as a list."""
        return obj.get_authorized_domains_list()


class OAuthConsentScreenCreateUpdateSerializer(serializers.ModelSerializer):
    """Serializer for creating/updating OAuthConsentScreen."""
    
    authorized_domains_list = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
        help_text='List of authorized domains'
    )
    
    class Meta:
        model = OAuthConsentScreen
        fields = (
            'app_name', 'app_description', 'app_logo', 'support_email', 'application_homepage',
            'privacy_policy_url', 'terms_of_service_url', 'authorized_domains',
            'authorized_domains_list', 'developer_contact_email', 'scope_descriptions',
            'scope_reasons', 'publishing_status'
        )
    
    def validate_app_name(self, value):
        """Validate app name."""
        if not value or not value.strip():
            raise serializers.ValidationError('App name is required.')
        if len(value.strip()) > 100:
            raise serializers.ValidationError('App name cannot exceed 100 characters.')
        return value.strip()
    
    def validate_support_email(self, value):
        """Validate support email."""
        if not value or not value.strip():
            raise serializers.ValidationError('Support email is required.')
        from django.core.validators import validate_email
        try:
            validate_email(value.strip())
        except:
            raise serializers.ValidationError('Please enter a valid email address.')
        return value.strip()
    
    def validate_developer_contact_email(self, value):
        """Validate developer contact email."""
        if not value or not value.strip():
            raise serializers.ValidationError('Developer contact email is required.')
        from django.core.validators import validate_email
        try:
            validate_email(value.strip())
        except:
            raise serializers.ValidationError('Please enter a valid email address.')
        return value.strip()
    
    def validate_app_logo(self, value):
        """Validate app logo URL."""
        if value and value.strip():
            from django.core.validators import URLValidator
            from django.core.exceptions import ValidationError
            validator = URLValidator()
            try:
                validator(value.strip())
            except ValidationError:
                raise serializers.ValidationError('Please enter a valid URL for the app logo.')
        return value.strip() if value else ''
    
    def validate_application_homepage(self, value):
        """Validate application homepage URL."""
        if value and value.strip():
            from django.core.validators import URLValidator
            from django.core.exceptions import ValidationError
            validator = URLValidator()
            try:
                validator(value.strip())
            except ValidationError:
                raise serializers.ValidationError('Please enter a valid URL for the application homepage.')
        return value.strip() if value else ''
    
    def validate_privacy_policy_url(self, value):
        """Validate privacy policy URL."""
        if value and value.strip():
            from django.core.validators import URLValidator
            from django.core.exceptions import ValidationError
            validator = URLValidator()
            try:
                validator(value.strip())
            except ValidationError:
                raise serializers.ValidationError('Please enter a valid URL for the privacy policy.')
        return value.strip() if value else ''
    
    def validate_terms_of_service_url(self, value):
        """Validate terms of service URL."""
        if value and value.strip():
            from django.core.validators import URLValidator
            from django.core.exceptions import ValidationError
            validator = URLValidator()
            try:
                validator(value.strip())
            except ValidationError:
                raise serializers.ValidationError('Please enter a valid URL for the terms of service.')
        return value.strip() if value else ''
    
    def validate_app_description(self, value):
        """Validate app description length."""
        if value and len(value) > 500:
            raise serializers.ValidationError('App description cannot exceed 500 characters.')
        return value.strip() if value else ''
    
    def validate_authorized_domains_list(self, value):
        """Validate authorized domains list. Accepts domains, URLs, localhost with ports, and IPs."""
        if not isinstance(value, list):
            raise serializers.ValidationError('Authorized domains must be a list.')
        
        import re
        from urllib.parse import urlparse
        
        normalized_domains = []
        
        for domain in value:
            if not domain or not isinstance(domain, str):
                continue
            
            domain = domain.strip()
            if not domain:
                continue
            
            # Try to parse as URL first
            try:
                # Add scheme if missing for urlparse
                if not domain.startswith(('http://', 'https://')):
                    test_url = f'http://{domain}'
                else:
                    test_url = domain
                
                parsed = urlparse(test_url)
                # Extract hostname and port
                hostname = parsed.hostname or domain
                port = parsed.port
                normalized = hostname + (f':{port}' if port else '')
            except:
                # If URL parsing fails, assume it's already a domain
                normalized = domain
            
            # Validate normalized domain format
            # Allow localhost with optional port
            if re.match(r'^localhost(:\d+)?$', normalized, re.IGNORECASE):
                normalized_domains.append(normalized)
                continue
            
            # Allow IP addresses with optional port
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$', normalized):
                normalized_domains.append(normalized)
                continue
            
            # Allow standard domain format (with optional port)
            domain_regex = re.compile(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}(:\d+)?$', re.IGNORECASE)
            if domain_regex.match(normalized):
                normalized_domains.append(normalized)
                continue
            
            # If none of the patterns match, it's invalid
            raise serializers.ValidationError(f'Invalid domain format: {domain}')
        
        return normalized_domains
    
    def validate(self, attrs):
        """Convert authorized_domains_list to authorized_domains string and validate scope_reasons."""
        if 'authorized_domains_list' in attrs:
            authorized_domains_list = attrs.pop('authorized_domains_list', [])
            # Filter out empty strings and join
            valid_domains = [d.strip() for d in authorized_domains_list if d and d.strip()]
            attrs['authorized_domains'] = '\n'.join(valid_domains)
        
        # Validate scope_reasons structure if provided
        if 'scope_reasons' in attrs and attrs['scope_reasons']:
            if not isinstance(attrs['scope_reasons'], dict):
                raise serializers.ValidationError({'scope_reasons': 'scope_reasons must be a dictionary.'})
            
            for scope, info in attrs['scope_reasons'].items():
                if not isinstance(info, dict):
                    raise serializers.ValidationError({
                        'scope_reasons': f'Invalid format for scope "{scope}". Expected object with description and reason.'
                    })
                if 'description' not in info or 'reason' not in info:
                    raise serializers.ValidationError({
                        'scope_reasons': f'Scope "{scope}" must have both "description" and "reason" fields.'
                    })
        
        return attrs
    
    def create(self, validated_data):
        """Create a new consent screen."""
        oauth_app = validated_data.pop('oauth_app')
        consent_screen = OAuthConsentScreen.objects.create(
            oauth_app=oauth_app,
            **validated_data
        )
        return consent_screen


