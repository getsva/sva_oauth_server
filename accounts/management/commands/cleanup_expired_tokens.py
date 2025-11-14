"""
Management command to clean up expired tokens and authorization codes.
Run this periodically (e.g., via cron) to prevent database bloat.
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from accounts.models import (
    EmailVerificationToken,
    OAuthAuthorizationCode,
    OAuthAccessToken,
    OAuthRefreshToken,
    OAuthAuthorizationRequest
)


class Command(BaseCommand):
    help = 'Clean up expired tokens and authorization codes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        now = timezone.now()
        
        # Clean up expired email verification tokens
        expired_email_tokens = EmailVerificationToken.objects.filter(
            expires_at__lt=now
        )
        email_count = expired_email_tokens.count()
        if not dry_run:
            expired_email_tokens.delete()
        self.stdout.write(
            self.style.SUCCESS(
                f"{'Would delete' if dry_run else 'Deleted'} {email_count} expired email verification tokens"
            )
        )
        
        # Clean up expired authorization codes
        expired_codes = OAuthAuthorizationCode.objects.filter(
            expires_at__lt=now
        )
        code_count = expired_codes.count()
        if not dry_run:
            expired_codes.delete()
        self.stdout.write(
            self.style.SUCCESS(
                f"{'Would delete' if dry_run else 'Deleted'} {code_count} expired authorization codes"
            )
        )
        
        # Clean up expired access tokens
        expired_access_tokens = OAuthAccessToken.objects.filter(
            expires_at__lt=now
        )
        access_count = expired_access_tokens.count()
        if not dry_run:
            expired_access_tokens.delete()
        self.stdout.write(
            self.style.SUCCESS(
                f"{'Would delete' if dry_run else 'Deleted'} {access_count} expired access tokens"
            )
        )
        
        # Clean up expired refresh tokens (only those with expiration)
        expired_refresh_tokens = OAuthRefreshToken.objects.filter(
            expires_at__isnull=False,
            expires_at__lt=now
        )
        refresh_count = expired_refresh_tokens.count()
        if not dry_run:
            expired_refresh_tokens.delete()
        self.stdout.write(
            self.style.SUCCESS(
                f"{'Would delete' if dry_run else 'Deleted'} {refresh_count} expired refresh tokens"
            )
        )
        
        # Clean up expired authorization requests
        expired_auth_requests = OAuthAuthorizationRequest.objects.filter(
            expires_at__lt=now,
            status=OAuthAuthorizationRequest.STATUS_PENDING
        )
        auth_request_count = expired_auth_requests.count()
        if not dry_run:
            # Update status to expired instead of deleting (for audit trail)
            expired_auth_requests.update(status=OAuthAuthorizationRequest.STATUS_EXPIRED)
        self.stdout.write(
            self.style.SUCCESS(
                f"{'Would mark as expired' if dry_run else 'Marked as expired'} {auth_request_count} expired authorization requests"
            )
        )
        
        # Clean up used email verification tokens older than 7 days
        old_used_tokens = EmailVerificationToken.objects.filter(
            is_used=True,
            created_at__lt=now - timezone.timedelta(days=7)
        )
        old_token_count = old_used_tokens.count()
        if not dry_run:
            old_used_tokens.delete()
        self.stdout.write(
            self.style.SUCCESS(
                f"{'Would delete' if dry_run else 'Deleted'} {old_token_count} old used email verification tokens"
            )
        )
        
        total = email_count + code_count + access_count + refresh_count + auth_request_count + old_token_count
        self.stdout.write(
            self.style.SUCCESS(
                f"\nTotal: {total} items {'would be cleaned up' if dry_run else 'cleaned up'}"
            )
        )

