# config/views.py

import time
import django
from django.db import connection
from django.conf import settings
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny


class HealthCheckView(APIView):
    """
    Professional health check endpoint that returns comprehensive service status.
    
    This endpoint is used by:
    - Load balancers for health checks
    - Monitoring systems (Prometheus, Datadog, etc.)
    - Kubernetes liveness/readiness probes
    - CI/CD pipelines for deployment verification
    
    Returns:
    - Overall service status
    - Database connectivity status
    - Timestamp
    - Environment information
    - Django version
    - Response time metrics
    """
    permission_classes = [AllowAny]

    def get(self, request):
        start_time = time.time()
        
        # Check database connectivity
        db_status = self._check_database()
        
        # Calculate response time
        response_time_ms = round((time.time() - start_time) * 1000, 2)
        
        # Determine overall health status
        overall_status = 'healthy' if db_status['status'] == 'connected' else 'degraded'
        http_status = 200 if overall_status == 'healthy' else 503
        
        # Build comprehensive response
        health_data = {
            'status': overall_status,
            'timestamp': timezone.now().isoformat(),
            'service': {
                'name': 'SVA OAuth Server',
                'version': getattr(settings, 'APP_VERSION', '1.0.0'),
                'environment': 'production' if not settings.DEBUG else 'development',
                'django_version': django.get_version(),
            },
            'checks': {
                'database': db_status,
            },
            'metrics': {
                'response_time_ms': response_time_ms,
            }
        }
        
        return Response(health_data, status=http_status)
    
    def _check_database(self):
        """
        Check database connectivity by executing a simple query.
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            return {
                'status': 'connected',
                'message': 'Database connection successful'
            }
        except Exception as e:
            return {
                'status': 'disconnected',
                'message': f'Database connection failed: {str(e)}'
            }

