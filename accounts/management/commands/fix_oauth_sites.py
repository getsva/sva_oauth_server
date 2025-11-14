"""
Management command to fix OAuth app site associations.
"""
from django.core.management.base import BaseCommand
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp


class Command(BaseCommand):
    help = 'Fix OAuth app site associations'

    def handle(self, *args, **options):
        site = Site.objects.get_current()
        self.stdout.write(f"\nAssociating OAuth apps with site: {site.domain} (ID: {site.id})\n")
        
        # Fix Google
        google_apps = SocialApp.objects.filter(provider='google')
        if google_apps.exists():
            for app in google_apps:
                if site not in app.sites.all():
                    app.sites.add(site)
                    self.stdout.write(self.style.SUCCESS(f'✓ Associated Google app "{app.name}" with site'))
                else:
                    self.stdout.write(self.style.SUCCESS(f'✓ Google app "{app.name}" already associated'))
        else:
            self.stdout.write(self.style.WARNING('⚠ No Google OAuth app found'))
        
        # Fix GitHub
        github_apps = SocialApp.objects.filter(provider='github')
        if github_apps.exists():
            for app in github_apps:
                if site not in app.sites.all():
                    app.sites.add(site)
                    self.stdout.write(self.style.SUCCESS(f'✓ Associated GitHub app "{app.name}" with site'))
                else:
                    self.stdout.write(self.style.SUCCESS(f'✓ GitHub app "{app.name}" already associated'))
        else:
            self.stdout.write(self.style.WARNING('⚠ No GitHub OAuth app found'))
        
        self.stdout.write(self.style.SUCCESS('\n✓ Done!\n'))

