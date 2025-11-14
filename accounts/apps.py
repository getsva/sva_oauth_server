from django.apps import AppConfig
import warnings


class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'
    
    def ready(self):
        import accounts.signals  # noqa
        
        # Suppress deprecation warnings from dj_rest_auth using deprecated django-allauth settings
        # These warnings are from dj_rest_auth library code, not our code
        # We've configured django-allauth correctly with ACCOUNT_USERNAME_REQUIRED and ACCOUNT_EMAIL_REQUIRED
        # The warnings occur because dj_rest_auth 7.0.1 still accesses deprecated settings
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

