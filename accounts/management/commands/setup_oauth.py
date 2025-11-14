from django.core.management.base import BaseCommand
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp
from django.conf import settings
import os


class Command(BaseCommand):
    help = 'Setup OAuth applications for Google and GitHub'

    def handle(self, *args, **options):
        # Get current site
        site = Site.objects.get_current()
        
        # Google OAuth
        google_client_id = os.getenv('GOOGLE_CLIENT_ID', '')
        google_client_secret = os.getenv('GOOGLE_CLIENT_SECRET', '')
        
        if google_client_id and google_client_secret:
            google_app, created = SocialApp.objects.get_or_create(
                provider='google',
                defaults={
                    'name': 'Google',
                    'client_id': google_client_id,
                    'secret': google_client_secret,
                }
            )
            
            if not created:
                google_app.client_id = google_client_id
                google_app.secret = google_client_secret
                google_app.save()
            
            google_app.sites.add(site)
            self.stdout.write(
                self.style.SUCCESS(f'✓ Google OAuth app {"created" if created else "updated"}')
            )
        else:
            self.stdout.write(
                self.style.WARNING('⚠ Google OAuth credentials not found in environment variables')
            )
        
        # GitHub OAuth
        github_client_id = os.getenv('GITHUB_CLIENT_ID', '')
        github_client_secret = os.getenv('GITHUB_CLIENT_SECRET', '')
        
        if github_client_id and github_client_secret:
            github_app, created = SocialApp.objects.get_or_create(
                provider='github',
                defaults={
                    'name': 'GitHub',
                    'client_id': github_client_id,
                    'secret': github_client_secret,
                }
            )
            
            if not created:
                github_app.client_id = github_client_id
                github_app.secret = github_client_secret
                github_app.save()
            
            github_app.sites.add(site)
            self.stdout.write(
                self.style.SUCCESS(f'✓ GitHub OAuth app {"created" if created else "updated"}')
            )
        else:
            self.stdout.write(
                self.style.WARNING('⚠ GitHub OAuth credentials not found in environment variables')
            )
        
        self.stdout.write(
            self.style.SUCCESS('\nOAuth setup complete!')
        )


