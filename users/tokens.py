from django.contrib.auth.tokens import PasswordResetTokenGenerator

class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            str(user.pk) + str(timestamp) + 
            str(user.email_is_verified) + 
            'email_verification'  # Tag the token for email verification
        )

email_verification_token_generator = EmailVerificationTokenGenerator()

class AccountRecoveryTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            str(user.pk) +  
            str(timestamp) + 
            'account_recovery'
        )

account_recovery_token_generator = AccountRecoveryTokenGenerator()


