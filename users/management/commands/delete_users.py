from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from users.models import CustomUser 
from django.contrib.auth import get_user_model

User = get_user_model() 
 
class Command(BaseCommand):
    help = "Delete unverified users after 48 hours and inactive users after 15 minutes, and clear pending emails after 24 hours."

    def handle(self, *args, **kwargs):
        now = timezone.now()

        # Delete users who haven't verified their email within 48 hours
        email_verification_threshold = now - timedelta(minutes=1)
        unverified_users = User.objects.filter(
            email_is_verified=False,
            date_joined__lte=email_verification_threshold # date_joined <= date threshold
        )
        unverified_count = unverified_users.count()
        unverified_users.delete()
        self.stdout.write(f'Successfully deleted {unverified_count} unverified users.')    

        # Clear pending emails 
        pending_email_threshold = now - timedelta(minutes=1)
        users_with_pending_emails = User.objects.filter(
            pending_email__isnull=False, 
            pending_email_created_at__lte=pending_email_threshold 
        )
        users_with_pending_emails.update(pending_email=None, pending_email_created_at=None)
        users_with_pending_emails_count = users_with_pending_emails.count()
        self.stdout.write(f'Successfully deleted {users_with_pending_emails_count} pending emails.')       

        # clear ogininal email field
        original_email_threshold = now - timedelta(hours=48) 
        users_with_original_emails = User.objects.filter(
            original_email__isnull=False,
            original_email_created_at__lte=original_email_threshold
        )
        users_with_original_emails.update(original_email=None, original_email_created_at=None)
        users_with_original_emails_count = users_with_original_emails.count()
        self.stdout.write(f'Successfully deleted {users_with_original_emails_count} original email.')

        # clear SignupAttemptEmail
        account_deleted_at_threshold = now - timedelta(minutes=15)
        emails_from_deleted_accounts = SignupAttemptEmail.objects.filter(
            account_deleted_at__lte=account_deleted_at_threshold
        ).delete()
        emails_from_deleted_accounts_count = emails_from_deleted_accounts.count()
        self.stdout.write(f'Successfully deleted {emails_from_deleted_accounts_count} email from deleted accounts.')

        # clear SignupAttemptIpAddress
        account_deleted_at_threshold = now - timedelta(minutes=15)
        ip_addresses_spam = SignupAttemptIpAddress.objects.filter(
            signup_date__lte=account_deleted_at_threshold
        ).delete()
        ip_addresses_spam_count = emails_from_deleted_accounts.count()
        self.stdout.write(f'Successfully removed signup restriction from {ip_addresses_spam_count} ip addresses.')