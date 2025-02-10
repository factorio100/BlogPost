from django.shortcuts import render, redirect, get_object_or_404
from django.http import Http404
from django.contrib.auth import login, get_user_model, update_session_auth_hash, logout, authenticate
from .forms import CustomLoginForm, CustomUserCreationForm, CustomUserProfileForm, ChangeEmailForm, ChangePasswordForm, DeleteAccountForm, ForgottenPasswordForm, RecoverAccountForm, ForgottenPasswordEmailForm
from django.contrib.auth.decorators import login_required
from .email_utils import send_verification_email, SIGNUP_COOLDOWN
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from .tokens import email_verification_token, account_recovery_token
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from datetime import timedelta
from django.utils import timezone
from .models import SignupAttemptEmail, SignupAttemptIpAddress
from django.contrib.sessions.models import Session
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

User = get_user_model() # to reference the user model as User instead of CustomUser

def get_user_ip(request):
    # Check for IP address in the 'X-Forwarded-For' header (used when behind a proxy)
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # 'X-Forwarded-For' can contain multiple IPs, so take the first one
        ip = x_forwarded_for.split(',')[0]
    else:
        # If not present, fallback to the remote IP address
        ip = request.META.get('REMOTE_ADDR')
    return ip

def check_user_token(uidb64, token, token_generator): 
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if token_generator.check_token(user, token): 
        return user

    return None

def custom_login_view(request):
    if request.method == 'POST':
        form = CustomLoginForm(data=request.POST) 
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('BlogPost:home')

    else:
        form = CustomLoginForm()

    context = {'form': form, 'title': 'Log in', 'site_key': settings.RECAPTCHA_SITE_KEY}
    return render(request, 'registration/login.html', context)

def custom_logout_view(request):
    if request.method == 'POST':
        logout(request)
        messages.success(request,'You have been logged out')

    return redirect('BlogPost:home')

# registration
def signup(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)

        # Check if the email has recently belonged to a deleted account
        email = request.POST.get('email')
        if SignupAttemptEmail.objects.filter(account_deleted_email=email).exists():
            messages.error(request, "You must wait 15 minutes before resigning up with this email.")
            return redirect('users:signup') 
        
        # Check for spam based on IP address
        ip_address_attempt = SignupAttemptIpAddress.objects.filter(
            ip_address=get_user_ip(request),
            signup_date__gt=timezone.now() - SIGNUP_COOLDOWN
        ).count()
        if ip_address_attempt >= 1:
            messages.error(request, "Too many signup attempts. Please try again later.")
            return redirect('BlogPost:home')

        if form.is_valid():
            # update date or create SignupAttemptIpAddress instance if new ip address
            ip_address, created = SignupAttemptIpAddress.objects.get_or_create(ip_address=get_user_ip(request))
            if not created:  
                ip_address.signup_date = timezone.now()
                ip_address.save()
                
            new_user = form.save()
            login(request, new_user)

            try:
                send_verification_email(
                    user=new_user, 
                    request=request,
                    url='users:verify_email', 
                    subject='Email verification',  
                    email=new_user.email
                )
                messages.success(request, "A verification email has been sent. Check your email.")
            except Exception as e:
                messages.error(request, f"An error occurred while sending the verification email: {e}")

            return redirect('BlogPost:home')

    else:
        form = CustomUserCreationForm()

    context = {'form': form, 'title': 'Sign up', 'site_key': settings.RECAPTCHA_SITE_KEY}
    return render(request, 'registration/signup.html', context)

def verify_email(request, uidb64, token):
    user = check_user_token(uidb64, token, token_generator=email_verification_token)
    if user:
        user.email_is_verified = True
        user.save()

        messages.success(request, 'Your email has been verified.')
        return redirect('BlogPost:home')

    else:
        messages.warning(request, 'The link is invalid.')
        return redirect('users:account')

# settings 
def profile(request, user_id):
    # use 'user_profile' name to avoid conflicts with base.html
    user_profile = get_object_or_404(User, id=user_id)
    context = {'user_profile': user_profile, 'title': 'Profile'}
    return render(request, 'settings/profile.html', context)

@login_required
def edit_profile(request, user_id):
    user = request.user
    user_profile = User.objects.get(id=user_id)
    if user_profile != request.user:
        raise Http404

    if request.method == 'POST':
        form = CustomUserProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            if 'clear_profile_picture' in request.POST:
                user.profile_picture.delete()  # deletes the file from storage
                user.profile_picture = None   # clears the field in the model
            form.save()
            return redirect('users:profile', user_id=user_id)  
    else:
        form = CustomUserProfileForm(instance=request.user)

    context = {'form': form, 'title': 'Edit profile'}
    return render(request, 'settings/edit_profile.html', context)

@login_required
def account(request): 
    deletion_time = request.user.date_joined + timedelta(days=2)
    remaining_time = deletion_time - timezone.now()
    remaining_days = remaining_time.days
    remaining_hours = remaining_time.seconds // 3600

    context = {'remaining_days': remaining_days, 'remaining_hours': remaining_hours, 'title': 'Account'}

    if request.method == "POST":
        user = request.user
        try:
            # Send verification email for new email
            if request.user.pending_email:
                send_verification_email(
                    user=user, 
                    request=request,
                    url='users:verify_new_email', 
                    subject='Email change',  
                    email=user.pending_email
                )   
                messages.success(request, "Verification email sent to your new email address.")

            # Send verification email for current email
            else:
                send_verification_email(
                    user=user, 
                    request=request,
                    url='users:verify_email', 
                    subject='Email verification',  
                    email=user.email
                )
                messages.success(request, "Verification email sent to your current email address.")
        except Exception as e:
            messages.error(request, f"An error occurred while sending the verification email: {e}")
            
    return render(request, 'settings/account.html', context)

@login_required
def change_email(request):
    if not request.user.email_is_verified or request.user.pending_email:
        raise Http404 

    if request.method == 'POST':
        form = ChangeEmailForm(request.POST, instance=request.user)

        if form.is_valid():
            if request.user.original_email: # prevent email change during account recovery period
               messages.error(request, 'You must wait before rechanging your email.')
               return redirect('users:account')

            user = form.save(commit=False)

            user.pending_email_created_at = timezone.now() # for clearing the pending email field after a period of time
            try:
                # send verification email to new email
                send_verification_email(
                    user=user, 
                    request=request,
                    url='users:verify_new_email', 
                    subject='Email change',  
                    email=user.pending_email
                )           

                # account recovery
                send_verification_email(
                    user=user, 
                    request=request,
                    url='users:recover_account',
                    subject='Email changed',
                    email=user.email
                )
                messages.success(request, "Verification email have been sent to your new email address.")
            except Exception as e:
                messages.error(request, f"An error occurred while sending the verification email: {e}")
            
            user.original_email = user.email
            user.original_email_created_at = timezone.now()

            user.save()

            return redirect('users:account')
            
    else:
        form = ChangeEmailForm(instance=request.user)

    context = {'form': form, 'title': 'Change email'}
    return render(request, 'settings/change_email.html', context)

def verify_new_email(request, uidb64, token):
    user = check_user_token(uidb64, token, token_generator=email_verification_token)
    if user:
        if user.pending_email:  # Ensure pending_email exists before updating
            user.email = user.pending_email
            user.pending_email = None
            user.email_is_verified = True  # Mark the new email as verified
            user.save()
            messages.success(request, "Your email has been successfully updated.")
            return redirect('BlogPost:home')              

        else:
            messages.error(request, "No pending email to update.")
            return redirect('users:account')

    else:
        messages.error(request, "The email verification link is invalid or has expired.")
        return redirect('users:account')

@login_required
def cancel_change_email(request):
    if request.method == 'POST':
        request.user.pending_email = None
        request.user.save()
        messages.success(request, 'Cancelled the email change.')
        return redirect('users:account')
        
    return redirect('users:account')

@login_required
def change_password(request): 
    if request.method == 'POST':
        form = ChangePasswordForm(request.POST, user=request.user)
        if form.is_valid():
            new_password = form.cleaned_data.get('new_password')
            log_out_after_change = form.cleaned_data.get('log_out')

            request.user.set_password(new_password)
            request.user.save()

            messages.success(request, "Your password has been successfully changed.")
            
            if log_out_after_change:
                sessions = Session.objects.filter(expire_date__gte=timezone.now()) # get non expired sessions 
                for session in sessions:
                    session_data = session.get_decoded() 
                    if session_data.get('_auth_user_id') == str(request.user.id): 
                        session.delete()

                logout(request)
                return redirect('BlogPost:home')
            else:
                update_session_auth_hash(request, request.user)
                return redirect('users:account')
            
    else:
        form = ChangePasswordForm(user=request.user)

    context = {'form': form, 'title': 'Change password'}
    return render(request, 'settings/change_password.html', context)

@login_required
def delete_account(request):
    if request.method == 'POST':
        form = DeleteAccountForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = request.user
            # prevent account deletion during recovery period
            if user.original_email:
                messages.error(request, 'you must wait before deleting your account due to a change in the email address.')
                return redirect('users:account')
            
            SignupAttemptEmail.objects.create(account_deleted_email=user.email)
    
            user.delete()
            messages.success(request, "Your account has been deleted successfully.")
            return redirect('BlogPost:home')  
    else:
        form = DeleteAccountForm(user=request.user)

    context = {'form': form, 'title': 'Account deletion', 'site_key': settings.RECAPTCHA_SITE_KEY}
    return render(request, 'settings/delete_account.html', context)

def forgotten_password_email(request):
    if request.method == 'POST':
        form = ForgottenPasswordEmailForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = User.objects.get(email=email)

            try:
                send_verification_email(
                    user=user, 
                    request=request,
                    url='users:forgotten_password',
                    subject='Forgotten password', 
                    email=email
                )
                messages.success(request, "A password reset email has been sent. Check your emails.")
            except Exception as e:
                messages.error(request, f"An error occurred while sending the password reset email: {e}")

            return redirect('users:login')

    else:
        form = ForgottenPasswordEmailForm()

    context = {'form': form, 'title': 'Forgotten password'}
    return render(request, 'settings/forgotten_password_email.html', context)

def forgotten_password(request, uidb64, token): 
    # user from forgotten_password_email()
    user = check_user_token(uidb64, token, token_generator=default_token_generator)

    if user:
        # Handle the form for password reset
        if request.method == 'POST':
            form = ForgottenPasswordForm(request.POST, user=user)
            if form.is_valid():
                new_password = form.cleaned_data.get('new_password')
                user.set_password(new_password)
                user.save()
                messages.success(request, "Your password has been successfully reset.")
                # logout active sessions
                sessions = Session.objects.filter(expire_date__gte=timezone.now()) # get non expired sessions 
                for session in sessions:
                    session_data = session.get_decoded() 
                    if session_data.get('_auth_user_id') == str(user.id): 
                        session.delete()

                return redirect('users:login')
        else:
            form = ForgottenPasswordForm(user=user)

        context = {'form': form, 'title': 'Password reset'}
        return render(request, 'settings/forgotten_password.html', context)

    else:
        messages.warning(request, 'The link is invalid.')
        return redirect('users:login')

def recover_account(request, uidb64, token):
    user = check_user_token(uidb64, token, token_generator=account_recovery_token)

    if user:
        if request.method == 'POST':
            form = RecoverAccountForm(request.POST, instance=user)
            if form.is_valid():
                new_password = form.cleaned_data.get('new_password')
                user.set_password(new_password)
                user.original_email = None
                user.pending_email = None
                user.save()
                messages.success(request, 'Your password has been reset.')
                # logout active sessions
                sessions = Session.objects.filter(expire_date__gte=timezone.now()) # get non expired sessions 
                for session in sessions:
                    session_data = session.get_decoded() 
                    if session_data.get('_auth_user_id') == str(user.id): 
                        session.delete()

                return redirect('BlogPost:home')

        else: 
            form = RecoverAccountForm(instance=user)

        context = {'form': form, 'user': user, 'title': 'Account recovery'}
        return render(request, 'settings/recover_account.html', context)

    else:
        messages.warning(request, 'The link is invalid.')

    return redirect('BlogPost:home')




