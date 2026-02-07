"""
Dashboard APIs & Services: developer-focused usage metrics for OAuth apps and API keys.
"""
from django.utils import timezone
from django.db.models import Count
from django.db.models.functions import TruncDate
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from .models import (
    OAuthApp,
    APIKey,
    OAuthAccessToken,
    OAuthAuthorizationCode,
    OAuthAuthorizationRequest,
)

# Supported time ranges (hours or days)
RANGE_HOURS = {
    '1 hour': 1,
    '6 hours': 6,
    '12 hours': 12,
    '1 day': 24,
    '2 days': 48,
    '4 days': 96,
    '7 days': 168,
    '14 days': 336,
    '30 days': 720,
}


def _parse_range(range_param):
    """Parse range query param into (hours, label). Default 1 day."""
    if not range_param or range_param not in RANGE_HOURS:
        return 24, '1 day'
    return RANGE_HOURS[range_param], range_param


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_usage(request):
    """
    GET /dashboard/usage/?range=1%20day

    Developer-focused metrics:
    - summary: oauth_apps_count, api_keys_count, api_keys_used_in_range
    - new_sign_ins: token issuances in range (time-series + total)
    - active_sessions: count of currently valid access tokens (right now)
    - failed_authorizations: denied + expired in range (with breakdown)
    - usage_by_app: per-app new sign-ins and active sessions
    - api_keys_summary: total keys, used in range, never used
    """
    user = request.user
    range_param = request.query_params.get('range', '1 day').strip()
    range_hours, _ = _parse_range(range_param)

    since = timezone.now() - timezone.timedelta(hours=range_hours)
    now = timezone.now()

    # User's OAuth apps and API keys (non-deleted)
    user_apps = list(
        OAuthApp.objects.filter(user=user, is_deleted=False).values('id', 'name')
    )
    user_app_ids = [a['id'] for a in user_apps]

    oauth_apps_count = len(user_app_ids)
    api_keys = list(
        APIKey.objects.filter(user=user, is_deleted=False).values(
            'id', 'name', 'last_used_at'
        )
    )
    api_keys_count = len(api_keys)
    api_keys_used_in_range = sum(1 for k in api_keys if k.get('last_used_at') and k['last_used_at'] >= since)
    api_keys_never_used = sum(1 for k in api_keys if not k.get('last_used_at'))

    # New sign-ins: access tokens issued in range (primary metric for "users who connected")
    bucket_by_date = range_hours >= 24
    new_sign_ins_series = []
    new_sign_ins_total = 0
    if user_app_ids:
        if bucket_by_date:
            tokens_qs = (
                OAuthAccessToken.objects.filter(
                    oauth_app_id__in=user_app_ids,
                    created_at__gte=since,
                )
                .annotate(date=TruncDate('created_at'))
                .values('date')
                .annotate(count=Count('id'))
                .order_by('date')
            )
            by_date = {}
            for row in tokens_qs:
                ds = row['date'].isoformat() if row['date'] else None
                if ds:
                    by_date[ds] = by_date.get(ds, 0) + row['count']
            new_sign_ins_series = [{'timestamp': d, 'value': v} for d, v in sorted(by_date.items())]
            new_sign_ins_total = sum(s['value'] for s in new_sign_ins_series)
        else:
            new_sign_ins_total = OAuthAccessToken.objects.filter(
                oauth_app_id__in=user_app_ids,
                created_at__gte=since,
            ).count()
            new_sign_ins_series = (
                [{'timestamp': since.isoformat(), 'value': new_sign_ins_total}]
                if new_sign_ins_total else []
            )

    # Active sessions: access tokens that are valid right now (not revoked, not expired)
    active_sessions = 0
    if user_app_ids:
        active_sessions = OAuthAccessToken.objects.filter(
            oauth_app_id__in=user_app_ids,
            is_revoked=False,
            expires_at__gt=now,
        ).count()

    # Failed authorizations: denied + expired in range
    denied_count = OAuthAuthorizationRequest.objects.filter(
        oauth_app_id__in=user_app_ids,
        status=OAuthAuthorizationRequest.STATUS_DENIED,
        created_at__gte=since,
    ).count()
    expired_count = OAuthAuthorizationRequest.objects.filter(
        oauth_app_id__in=user_app_ids,
        status=OAuthAuthorizationRequest.STATUS_EXPIRED,
        created_at__gte=since,
    ).count()
    failed_authorizations_total = denied_count + expired_count

    # Usage by app: per-app new sign-ins in range and active sessions now
    usage_by_app = []
    for app in user_apps:
        app_id = app['id']
        new_in_range = OAuthAccessToken.objects.filter(
            oauth_app_id=app_id,
            created_at__gte=since,
        ).count()
        active_now = OAuthAccessToken.objects.filter(
            oauth_app_id=app_id,
            is_revoked=False,
            expires_at__gt=now,
        ).count()
        usage_by_app.append({
            'app_id': app_id,
            'app_name': app['name'],
            'new_sign_ins': new_in_range,
            'active_sessions': active_now,
        })
    # Sort by new sign-ins descending, then active sessions
    usage_by_app.sort(key=lambda x: (-x['new_sign_ins'], -x['active_sessions']))

    return Response(
        {
            'summary': {
                'oauth_apps_count': oauth_apps_count,
                'api_keys_count': api_keys_count,
                'api_keys_used_in_range': api_keys_used_in_range,
                'api_keys_never_used': api_keys_never_used,
            },
            'new_sign_ins': {
                'series': new_sign_ins_series,
                'total': new_sign_ins_total,
            },
            'active_sessions': active_sessions,
            'failed_authorizations': {
                'denied_count': denied_count,
                'expired_count': expired_count,
                'total': failed_authorizations_total,
            },
            'usage_by_app': usage_by_app,
        },
        status=status.HTTP_200_OK,
    )
