"""
Management command to check OAuth app configuration.
"""
from django.core.management.base import BaseCommand
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp


class Command(BaseCommand):
    help = 'Check OAuth application configuration'

    def handle(self, *args, **options):
        site = Site.objects.get_current()
        self.stdout.write(f"\nCurrent Site: {site.domain} (ID: {site.id})\n")
        
        # Check Google
        google_apps = SocialApp.objects.filter(provider='google')
        if google_apps.exists():
            self.stdout.write(self.style.SUCCESS('✓ Google OAuth app found:'))
            for app in google_apps:
                sites_list = [s.domain for s in app.sites.all()]
                self.stdout.write(f"  - Name: {app.name}")
                self.stdout.write(f"    Client ID: {app.client_id[:20]}..." if len(app.client_id) > 20 else f"    Client ID: {app.client_id}")
                self.stdout.write(f"    Sites: {', '.join(sites_list) if sites_list else 'None'}")
                if site not in app.sites.all():
                    self.stdout.write(self.style.WARNING(f"    ⚠ Not associated with current site ({site.domain})"))
                    self.stdout.write(self.style.WARNING(f"    Run: app.sites.add(site) to fix"))
                else:
                    self.stdout.write(self.style.SUCCESS(f"    ✓ Associated with current site"))
        else:
            self.stdout.write(self.style.ERROR('✗ Google OAuth app NOT found'))
            self.stdout.write(self.style.WARNING('  Create it in Django Admin or run: python manage.py setup_oauth'))
        
        self.stdout.write("")
        
        # Check GitHub
        github_apps = SocialApp.objects.filter(provider='github')
        if github_apps.exists():
            self.stdout.write(self.style.SUCCESS('✓ GitHub OAuth app found:'))
            for app in github_apps:
                sites_list = [s.domain for s in app.sites.all()]
                self.stdout.write(f"  - Name: {app.name}")
                self.stdout.write(f"    Client ID: {app.client_id[:20]}..." if len(app.client_id) > 20 else f"    Client ID: {app.client_id}")
                self.stdout.write(f"    Sites: {', '.join(sites_list) if sites_list else 'None'}")
                if site not in app.sites.all():
                    self.stdout.write(self.style.WARNING(f"    ⚠ Not associated with current site ({site.domain})"))
                    self.stdout.write(self.style.WARNING(f"    Run: app.sites.add(site) to fix"))
                else:
                    self.stdout.write(self.style.SUCCESS(f"    ✓ Associated with current site"))
        else:
            self.stdout.write(self.style.ERROR('✗ GitHub OAuth app NOT found'))
            self.stdout.write(self.style.WARNING('  Create it in Django Admin or run: python manage.py setup_oauth'))
        
        self.stdout.write("\n")

