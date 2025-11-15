"""
Django settings for sva-o-auth project.

Environment Configuration:
---------------------------
This settings file automatically configures itself based on the ENVIRONMENT variable.
You can use separate .env files for different environments:

1. For Local Development:
   - Use .env.local file
   - Or set ENVIRONMENT=development system environment variable
   - DEBUG will be automatically set to True
   - Console email backend will be used
   - Less strict security settings

2. For Production:
   - Use .env.production file
   - Or set ENVIRONMENT=production system environment variable
   - DEBUG will be automatically set to False (security requirement)
   - SMTP email backend will be used
   - Production security settings will be enabled (HTTPS, secure cookies, etc.)

File Loading Priority:
- System environment variable ENVIRONMENT takes precedence
- Then loads .env.local (development) or .env.production (production)
- Falls back to .env if environment-specific file doesn't exist

All environment variables should be defined in the appropriate .env file.
"""
import os
import warnings
from pathlib import Path
from datetime import timedelta
import environ
import dj_database_url

# --- Environment Variable Setup ---
env = environ.Env(
    DEBUG=(bool, False),
    ENVIRONMENT=(str, 'development')
)

BASE_DIR = Path(__file__).resolve().parent.parent

# --- Environment Detection ---
# First, try to get ENVIRONMENT from system environment variable (for deployment platforms)
# Then try to read from .env file, then from environment-specific files
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development').lower()

# Load environment-specific .env file
# Priority: .env.local (development) or .env.production (production)
# Fallback to .env if environment-specific file doesn't exist
if ENVIRONMENT == 'production':
    env_file = BASE_DIR / '.env.production'
    if not env_file.exists():
        # Fallback to .env if .env.production doesn't exist
        env_file = BASE_DIR / '.env'
else:
    # Development environment
    env_file = BASE_DIR / '.env.local'
    if not env_file.exists():
        # Fallback to .env if .env.local doesn't exist
        env_file = BASE_DIR / '.env'

# Read the appropriate .env file
if env_file.exists():
    environ.Env.read_env(env_file)
    # Re-read ENVIRONMENT from the loaded file (it may override the system env)
    ENVIRONMENT = env('ENVIRONMENT', default=ENVIRONMENT).lower()

IS_PRODUCTION = ENVIRONMENT == 'production'
IS_DEVELOPMENT = ENVIRONMENT == 'development'

# Suppress deprecation warnings from dj_rest_auth using deprecated django-allauth settings
# These warnings are from dj_rest_auth library code (version 7.0.1), not our code
# We've configured django-allauth correctly with ACCOUNT_USERNAME_REQUIRED and ACCOUNT_EMAIL_REQUIRED
# The warnings occur because dj_rest_auth still accesses deprecated USERNAME_REQUIRED and EMAIL_REQUIRED
warnings.filterwarnings(
    'ignore',
    message=r'.*USERNAME_REQUIRED is deprecated.*',
    category=UserWarning
)
warnings.filterwarnings(
    'ignore',
    message=r'.*EMAIL_REQUIRED is deprecated.*',
    category=UserWarning
)

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# --- Core Django Settings ---
# Auto-configure DEBUG based on environment if not explicitly set
# In production, DEBUG should always be False for security
if 'DEBUG' in os.environ:
    DEBUG = env('DEBUG')
else:
    DEBUG = IS_DEVELOPMENT  # Auto-set based on environment

# Ensure DEBUG is False in production (security requirement)
if IS_PRODUCTION:
    DEBUG = False

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('DJANGO_SECRET_KEY', default='django-insecure-default-key-for-dev') # Added default for safety

# ALLOWED_HOSTS - must include your Azure App Service domain
# For Azure App Service, you MUST set this in environment variables:
# ALLOWED_HOSTS=oauth-api.azurewebsites.net,oauth-api.getsva.com
# Or set it in Azure Portal > Configuration > Application Settings
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['127.0.0.1', 'localhost'])


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    
    # Third party apps
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_simplejwt',
    'corsheaders',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'allauth.socialaccount.providers.github',
    'dj_rest_auth',
    'dj_rest_auth.registration',
    
    # Local apps
    'accounts',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Serve static files efficiently in production
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'config.middleware.HealthCheckCommonMiddleware',  # Custom middleware to prevent redirect loops
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

# Data upload settings - prevent DoS attacks
DATA_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 1000

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# --- Database ---
# Use a default SQLite database if DATABASE_URL is not set (useful for collectstatic, migrations, etc.)
# In production, DATABASE_URL should always be set
database_url = env('DATABASE_URL', default='')
if database_url:
    DATABASES = {
        'default': dj_database_url.config(
            default=database_url,
            conn_max_age=600,
            ssl_require=env('DB_SSL_REQUIRE', default=False, cast=bool)
        )
    }
else:
    # Fallback to SQLite for development or when DATABASE_URL is not set (e.g., during collectstatic)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }


# Custom User Model
AUTH_USER_MODEL = 'accounts.User'

# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# WhiteNoise configuration for serving static files in production
# WhiteNoise allows your Django app to serve its own static files efficiently
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Django Allauth Settings
SITE_ID = 1

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

# Account settings (updated for django-allauth 0.57+)
ACCOUNT_LOGIN_METHODS = {'email'}
# Explicitly set username and email requirements (using new format to avoid deprecation warnings)
# These settings prevent dj_rest_auth from checking deprecated USERNAME_REQUIRED and EMAIL_REQUIRED
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*', 'password2*']
ACCOUNT_EMAIL_VERIFICATION = 'mandatory'
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_USER_MODEL_USERNAME_FIELD = None

# Social Account Settings
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_EMAIL_VERIFICATION = 'none'  # We'll handle OAuth email verification differently
SOCIALACCOUNT_QUERY_EMAIL = True  # Request email from OAuth providers
SOCIALACCOUNT_STORE_TOKENS = False  # Don't store OAuth tokens (we use JWT)
SOCIALACCOUNT_REQUIRED = False  # Don't require social account connection

# REST Framework Settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    # Security: Limit request size to prevent DoS attacks
    'DEFAULT_PARSER_CLASSES': (
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ),
}

# --- Internal Service-to-Service Communication ---
INTERNAL_SERVICE_TOKEN = env('INTERNAL_SERVICE_TOKEN', default='dev-shared-secret')
INTERNAL_SERVICE_HEADER = env('INTERNAL_SERVICE_HEADER', default='X-Service-Token')

# DATA_TOKEN_SECRET must match sva_server backend - use same default for local development
DATA_TOKEN_SECRET = env('DATA_TOKEN_SECRET', default='dev-data-token-secret')
DATA_TOKEN_ALGORITHM = env('DATA_TOKEN_ALGORITHM', default='HS256')
DATA_TOKEN_TTL_SECONDS = env.int('DATA_TOKEN_TTL_SECONDS', default=300)
DATA_TOKEN_ISSUER = env('DATA_TOKEN_ISSUER', default='sva_oauth')
INTERNAL_SERVICE_TIMEOUT = env.int('INTERNAL_SERVICE_TIMEOUT', default=5)

# Configure consent URL based on environment
if IS_DEVELOPMENT:
    CORE_CONSENT_URL = env('CORE_CONSENT_URL', default='http://localhost:8080/consent')
else:
    # Production: use environment variable or default production URL
    CORE_CONSENT_URL = env('CORE_CONSENT_URL', default='https://app.getsva.com/consent')
AUTHORIZATION_REQUEST_TTL_SECONDS = env.int('AUTHORIZATION_REQUEST_TTL_SECONDS', default=600)

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(
        hours=env.int('JWT_ACCESS_TOKEN_LIFETIME_HOURS', default=1)
    ),
    'REFRESH_TOKEN_LIFETIME': timedelta(
        days=env.int('JWT_REFRESH_TOKEN_LIFETIME_DAYS', default=7)
    ),
    'ROTATE_REFRESH_TOKENS': env('JWT_ROTATE_REFRESH_TOKENS', default=True, cast=bool),
    'BLACKLIST_AFTER_ROTATION': env('JWT_BLACKLIST_AFTER_ROTATION', default=True, cast=bool),
    'UPDATE_LAST_LOGIN': env('JWT_UPDATE_LAST_LOGIN', default=True, cast=bool),
    'ALGORITHM': env('JWT_ALGORITHM', default='HS256'),
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

# --- CORS Settings ---
if IS_DEVELOPMENT:
    # Development: Allow all localhost origins
    CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=[
        "http://localhost:5173",  # Vite default port
        "http://localhost:8081",  # Frontend port
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8081",
        "http://127.0.0.1:3000",
    ])
else:
    # Production: Only allow configured frontend URL
    CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=[])

CORS_ALLOW_CREDENTIALS = True
# Additional CORS security
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]
# Prevent wildcard origins when credentials are allowed
if IS_PRODUCTION and not CORS_ALLOWED_ORIGINS:
    import warnings
    warnings.warn('CORS_ALLOWED_ORIGINS is empty in production! This will block all cross-origin requests.', UserWarning)

# --- Security Settings (Production) ---
if IS_PRODUCTION:
    # CRITICAL: Tell Django to trust Azure App Service's reverse proxy headers
    # Azure App Service sits behind a reverse proxy, and Django needs to know
    # that requests are already HTTPS by checking the X-Forwarded-Proto header.
    # Without this, SECURE_SSL_REDIRECT will cause infinite redirect loops.
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    
    SECURE_SSL_REDIRECT = env('SECURE_SSL_REDIRECT', default=True, cast=bool)
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    # Additional security headers
    SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
    # Prevent clickjacking
    X_CONTENT_TYPE_OPTIONS = 'nosniff'
else:
    # Development security settings (less strict)
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False

# --- Email Settings ---
# Auto-configure email backend based on environment
EMAIL_BACKEND_TYPE = env('EMAIL_BACKEND', default='smtp' if IS_PRODUCTION else 'console').lower()

if EMAIL_BACKEND_TYPE == 'console' or (IS_DEVELOPMENT and EMAIL_BACKEND_TYPE != 'smtp'):
    # Use console backend for development/testing
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
else:
    # Use SMTP backend for production
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = env('EMAIL_HOST', default='smtp.gmail.com')
    EMAIL_PORT = env.int('EMAIL_PORT', default=587)
    EMAIL_USE_TLS = env('EMAIL_USE_TLS', default=True, cast=bool)
    EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='your-email@gmail.com')
    EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD', default='your-app-password')
    DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default='no-reply@yourdomain.com')

# --- Frontend URL Configuration ---
# This is used in email links (verification, password reset, etc.) and OAuth redirects
# Set this in your environment variables for production
if IS_DEVELOPMENT:
    FRONTEND_URL = env('FRONTEND_URL', default='http://localhost:8081')
else:
    # Production: use environment variable or default to getsva.com
    FRONTEND_URL = env('FRONTEND_URL', default='https://getsva.com')

# OAuth Provider Settings
SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'SCOPE': [
            'profile',
            'email',
        ],
        'AUTH_PARAMS': {
            'access_type': 'online',
        },
        'OAUTH_PKCE_ENABLED': False,  # Disabled for frontend-initiated flow
    },
    'github': {
        'SCOPE': [
            'user:email',
        ],
    }
}

# Custom Social Account Adapter for OAuth redirects
SOCIALACCOUNT_ADAPTER = 'accounts.adapters.CustomSocialAccountAdapter'

# Configure OAuth apps via admin or environment
# For production, configure these in Django Admin under Social Applications

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO' if DEBUG else 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'accounts': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
}

# Optional: Create logs directory for file logging in production
# Uncomment and configure file handler above if needed
# if not DEBUG:
#     logs_dir = BASE_DIR / 'logs'
#     logs_dir.mkdir(exist_ok=True)

