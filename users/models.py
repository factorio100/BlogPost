from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone

class CustomBaseUserManager(BaseUserManager):
	def create_user(self, username, email, password=None, **other_fields):
		if not email:
			raise ValueError('The Email field must be set')
			
		user = self.model(username=username, email=self.normalize_email(email), **other_fields)
		user.set_password(password)
		user.save(using=self._db)
		return user

	def create_superuser(self,username, email, password=None, **other_fields):
		other_fields.setdefault('is_active', True)
		other_fields.setdefault('is_staff', True)
		other_fields.setdefault('is_superuser', True)
		return self.create_user(username, email, password, **other_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
	username = models.CharField(max_length=50, unique=True)  
	email = models.EmailField(max_length=50, unique=True) 
	
	profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)

	is_active = models.BooleanField(default=True)
	is_staff = models.BooleanField(default=False)
	is_superuser = models.BooleanField(default=False)

	date_joined = models.DateTimeField(default=timezone.now)

	USERNAME_FIELD = 'email' # login fields: email, password
	REQUIRED_FIELDS = ['username'] 

	# email verification
	email_is_verified = models.BooleanField(default=False)
	last_email_sent = models.DateTimeField(null=True, blank=True)   

	# changing email
	pending_email = models.EmailField(max_length=50, null=True, blank=True, unique=True)
	pending_email_created_at = models.DateTimeField(null=True, blank=True) # Pending email field will be cleared after a period of time 

	# account recovery
	last_forgotten_password_email_sent = models.DateTimeField(null=True, blank=True) # Cooldown for forgotten password email
	original_email = models.EmailField(max_length=50, null=True, blank=True) 
	original_email_created_at = models.DateTimeField(null=True, blank=True)

	objects = CustomBaseUserManager()

	def __str__(self):
		return self.username # display the username under "Change user" in admin page when clicking on un user

class SignupAttemptEmail(models.Model):
	# store deleted account email, after 15 minutes it will be cleared
	account_deleted_email = models.EmailField(max_length=50, null=True, blank=True)
	account_deleted_at = models.DateTimeField(null=True, blank=True)
	
class SignupAttemptIpAddress(models.Model):
	ip_address = models.GenericIPAddressField(null=True, blank=True)
	signup_date = models.DateTimeField(null=True, blank=True)