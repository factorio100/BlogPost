from django.utils import timezone
from datetime import timedelta
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from .tokens import email_verification_token_generator, account_recovery_token_generator
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.urls import reverse
from django.conf import settings

SIGNUP_COOLDOWN = timedelta(minutes=10) 
FORGOTTEN_PASSWORD_COOLDOWN = timedelta(minutes=15)

def cooldown(COOLDOWN, last_email_sent):
	if last_email_sent is None or timezone.now() - last_email_sent >= COOLDOWN:
		return True
	else:
		messages.warning(request, "You must wait before sending another verification email.")
		return False

def send_verification_email(user, request, url, subject, email):
	# for sending verification email when signing up, changing email
	if url == 'users:verify_email' or url == 'users:verify_new_email':
		if not cooldown(COOLDOWN=SIGNUP_COOLDOWN, last_email_sent=user.last_email_sent):
			return False	
	
	# for sending forgotten password verification email
	elif url == 'users:forgotten_password':
		if not cooldown(COOLDOWN=FORGOTTEN_PASSWORD_COOLDOWN, last_email_sent=user.last_forgotten_password_email_sent):
			return False
	else:
		pass

	current_site = get_current_site(request)

	uidb64 = urlsafe_base64_encode(force_bytes(user.id))

	# Determine which token to use based on the URL (forgotten password/account recovery use default token)
	if url in ['users:verify_email', 'users:verify_new_email']:
		# Custom token for email verification
		token = email_verification_token_generator.make_token(user)   

	elif url == 'users:forgotten_password':
		# Default token for password reset
		token = default_token_generator.make_token(user)
		
	else:
		# Custom token for account recovery
		token = account_recovery_token_generator.make_token(user)

	reverse_url = reverse(url, kwargs={'uidb64': uidb64, 'token': token})
	domain = get_current_site(request).domain 
	
	if settings.DEBUG == True:
		verification_url = f"http://{domain}{reverse_url}"
	else:
		verification_url = f"https://{domain}{reverse_url}"

	# verify email registration
	if url == 'users:verify_email':
		message = (
			f"To complete your registration at {domain}, click the link:" 
			f"<{verification_url}>."
		)
	# verify new email
	elif url == 'users:verify_new_email' :
		message = f"To use your new email for {domain}, click the link: <{verification_url}>"
	# forgotten password
	elif url == 'users:forgotten_password':
		message = f"To reset your password for {domain}, click the link: <{verification_url}>"
	# account recovery
	else:
		message = (
		f"Your email for {domain} has been changed, if you didn't change your email,"
	 	f"click this link to reset your email and password: <{verification_url}>"
	)

	email_message = EmailMessage(subject, message, to=[email])
	email_message.send()

	user.last_email_sent = timezone.now()
	user.save()

	return True

