from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type

class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            str(user.pk) + str(timestamp) + 
            str(user.email_is_verified) + 
            'email_verification'  # Tag the token for email verification
        )

email_verification_token = EmailVerificationTokenGenerator()

class AccountRecoveryTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            text_type(user.pk) +  
            text_type(timestamp) + 
            'account_recovery'
        )

account_recovery_token = AccountRecoveryTokenGenerator()


