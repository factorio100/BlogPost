from django.core.management.base import BaseCommand
from users.models import CustomUser, SignupAttemptEmail, SignupAttemptIpAddress

class Command(BaseCommand):
	help = 'Deletes instances of MyModel'

	def handle(self, *args, **kwargs):
		CustomUser.objects.filter(is_superuser=False).delete()
		SignupAttemptEmail.objects.all().delete()
		SignupAttemptIpAddress.objects.all().delete()

