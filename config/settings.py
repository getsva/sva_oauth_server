"""
Django settings for sva-o-auth project.
"""
import os
import warnings
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv
import dj_database_url

load_dotenv()

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

# SECURITY WARNING: don't run with debug turned on in production!
# Define DEBUG first as it's used in SECRET_KEY validation below
DEBUG = os.getenv('DEBUG', 'False') == 'True'

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    if DEBUG:
        # Only allow None in development with explicit warning
        import warnings
        warnings.warn(
            'SECRET_KEY is not set! Using a temporary key for development only. '
            'Set SECRET_KEY environment variable for production.',
            UserWarning
        )
        SECRET_KEY = 'django-insecure-dev-key-change-in-production-' + os.urandom(32).hex()
    else:
        raise ValueError(
            'SECRET_KEY environment variable must be set in production! '
            'Generate a secure key using: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"'
        )

# ALLOWED_HOSTS - must include your Azure App Service domain
# For Azure App Service, you MUST set this in environment variables:
# ALLOWED_HOSTS=oauth-api.azurewebsites.net,oauth-api.getsva.com
# Or set it in Azure Portal > Configuration > Application Settings
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
if not DEBUG:
    # In production, ensure ALLOWED_HOSTS is properly configured
    if not ALLOWED_HOSTS or ALLOWED_HOSTS == ['localhost', '127.0.0.1']:
        import warnings
        warnings.warn('ALLOWED_HOSTS should be configured for production!')


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


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases
# Use a default SQLite database if DATABASE_URL is not set (useful for collectstatic, migrations, etc.)
# In production, DATABASE_URL should always be set
database_url = os.getenv('DATABASE_URL', '')
if database_url:
    DATABASES = {
        'default': dj_database_url.config(
            default=database_url,
            conn_max_age=600,
            ssl_require=os.getenv('DB_SSL_REQUIRE', 'False') == 'True'
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

# Internal orchestration defaults
# CRITICAL: These must be set in production via environment variables
INTERNAL_SERVICE_TOKEN = os.getenv('INTERNAL_SERVICE_TOKEN')
if not INTERNAL_SERVICE_TOKEN:
    if DEBUG:
        INTERNAL_SERVICE_TOKEN = 'dev-shared-secret-change-in-production'
        import warnings
        warnings.warn('INTERNAL_SERVICE_TOKEN not set, using insecure default for development only!', UserWarning)
    else:
        raise ValueError('INTERNAL_SERVICE_TOKEN environment variable must be set in production!')

INTERNAL_SERVICE_HEADER = os.getenv('INTERNAL_SERVICE_HEADER', 'X-Service-Token')

DATA_TOKEN_SECRET = os.getenv('DATA_TOKEN_SECRET')
if not DATA_TOKEN_SECRET:
    if DEBUG:
        DATA_TOKEN_SECRET = 'dev-data-token-secret-change-in-production'
        import warnings
        warnings.warn('DATA_TOKEN_SECRET not set, using insecure default for development only!', UserWarning)
    else:
        raise ValueError('DATA_TOKEN_SECRET environment variable must be set in production!')

DATA_TOKEN_ALGORITHM = os.getenv('DATA_TOKEN_ALGORITHM', 'HS256')
# Use local development URL when DEBUG is True, otherwise use production URL
if DEBUG:
    CORE_CONSENT_URL = os.getenv('CORE_CONSENT_URL', 'http://localhost:8080/consent')
else:
    CORE_CONSENT_URL = os.getenv('CORE_CONSENT_URL', 'https://app.getsva.com/consent')
AUTHORIZATION_REQUEST_TTL_SECONDS = int(os.getenv('AUTHORIZATION_REQUEST_TTL_SECONDS', '600'))

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

# CORS Settings
if DEBUG:
    # Development: Allow all localhost origins
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:5173",  # Vite default port
        "http://localhost:8081",  # Frontend port
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8081",
        "http://127.0.0.1:3000",
    ]
else:
    # Production: Only allow configured frontend URL
    frontend_url = os.getenv('FRONTEND_URL', '')
    if frontend_url:
        CORS_ALLOWED_ORIGINS = [frontend_url]
    else:
        # Fallback: allow from environment variable
        cors_origins = os.getenv('CORS_ALLOWED_ORIGINS', '').split(',')
        CORS_ALLOWED_ORIGINS = [origin.strip() for origin in cors_origins if origin.strip()]

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
if not DEBUG and not CORS_ALLOWED_ORIGINS:
    import warnings
    warnings.warn('CORS_ALLOWED_ORIGINS is empty in production! This will block all cross-origin requests.', UserWarning)

# Security settings for production
if not DEBUG:
    # CRITICAL: Tell Django to trust Azure App Service's reverse proxy headers
    # Azure App Service sits behind a reverse proxy, and Django needs to know
    # that requests are already HTTPS by checking the X-Forwarded-Proto header.
    # Without this, SECURE_SSL_REDIRECT will cause infinite redirect loops.
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    
    SECURE_SSL_REDIRECT = os.getenv('SECURE_SSL_REDIRECT', 'True') == 'True'  # Default to True in production
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

# Email Configuration
EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True') == 'True'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'noreply@svaoauth.com')

# Frontend URL for email verification links and OAuth redirects
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:8081')

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

