# config/middleware.py

from django.middleware.common import CommonMiddleware


class HealthCheckCommonMiddleware(CommonMiddleware):
    """
    Custom CommonMiddleware that skips APPEND_SLASH redirect for health check endpoints.
    This prevents 301 redirect loops on Azure App Service and other platforms.
    
    Azure App Service can cause redirect loops when:
    - Django's CommonMiddleware tries to append a trailing slash
    - Azure's reverse proxy adds/removes slashes
    - The health check endpoint is at the root path
    
    This middleware prevents redirects for health check paths.
    """
    
    # Health check paths that should never be redirected
    HEALTH_CHECK_PATHS = ['', '/', '/health', '/health/']
    
    def should_redirect(self, request, path):
        """
        Override to prevent redirect for health check paths.
        """
        # Normalize the path for comparison
        normalized_path = path.rstrip('/')
        # Check if this is a health check path
        if normalized_path in ['', 'health']:
            return False
        # For all other paths, use the default behavior
        return super().should_redirect(request, path)
    
    def process_request(self, request):
        """
        Skip APPEND_SLASH redirect for health check paths to prevent redirect loops.
        """
        # Normalize the path for comparison
        normalized_path = request.path.rstrip('/')
        
        # Skip redirect for health check paths
        if normalized_path in ['', 'health']:
            # Let the request pass through without redirect
            # This prevents the 301 redirect loop on Azure App Service
            return None
        
        # For all other paths, use the default CommonMiddleware behavior
        return super().process_request(request)

