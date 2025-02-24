from django.contrib.auth import get_user_model
from django import forms
from .models import CustomUser
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django_recaptcha.fields import ReCaptchaField
from django.forms.widgets import ClearableFileInput

User = get_user_model()

# registration
class CustomUserCreationForm(UserCreationForm):
    recaptcha = ReCaptchaField()

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'password1', 'password2']

    def clean_email(self): # using lowercase conversion for emails
        email = self.cleaned_data.get('email').lower()    
        if CustomUser.objects.filter(email=email).exists():
                raise forms.ValidationError("This email is already in use.")
        # Else, email value is validated
        # The method must return the validated value, or else Django will assume the field is missing
        return email 

class CustomLoginForm(AuthenticationForm):
    recaptcha = ReCaptchaField()   

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['username'].label = 'Email'
        self.fields['username'].widget = forms.EmailInput()
    

# settings
class CustomClearableFileInput(ClearableFileInput):
    template_name = 'widgets/clearable_file_input.html' # custom template 

class CustomUserProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'profile_picture']
        widgets = {
            'profile_picture': CustomClearableFileInput(),
        }

class ChangeEmailForm(forms.ModelForm):
    password = forms.CharField(label="Password", widget=forms.PasswordInput, required=True)

    class Meta:
        model = CustomUser
        fields = ['pending_email']
        labels = {'pending_email': 'New email'}

    def clean_pending_email(self): 
        new_email = self.cleaned_data.get('pending_email').lower()  # convert to lowercase

        if (
            User.objects.filter(email=new_email).exists() or 
            User.objects.filter(pending_email=new_email).exists() or 
            User.objects.filter(original_email=new_email).exists()
        ):
            raise forms.ValidationError("This email address is already in use.")

        return new_email

    def clean_password(self):
        password_value = self.cleaned_data.get('password')
        if not self.instance.check_password(password_value):
            raise forms.ValidationError("The password you entered was incorrect.")
        return password_value

class ChangePasswordForm(forms.Form):
    password = forms.CharField(label="Current Password", widget=forms.PasswordInput, required=True)
    new_password = forms.CharField(label="New password", widget=forms.PasswordInput, required=True)
    new_password_confirm = forms.CharField(label="Confirm new password", widget=forms.PasswordInput, required=True)
    log_out = forms.BooleanField(label="Log out after changing the password", required=False, initial=True)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if not self.user.check_password(password):
            raise forms.ValidationError("The current password is incorrect.")
        return password

    def clean_new_password(self):
        password_value = self.cleaned_data.get('new_password')

        # Use Django's built-in password validators (password format)
        try:
            validate_password(password_value, self.user)
        except ValidationError as e:
            raise forms.ValidationError(e.messages)

        return password_value

    def clean(self):
        cleaned_data = super().clean()
        new_password_input = cleaned_data.get('new_password')
        new_password_confirm_input = cleaned_data.get('new_password_confirm')

        if new_password_input != new_password_confirm_input:
            raise forms.ValidationError("The new passwords do not match.")

        return cleaned_data

class DeleteAccountForm(forms.Form):
    password = forms.CharField(label="Password", widget=forms.PasswordInput,required=True)
    recaptcha = ReCaptchaField()

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if not self.user.check_password(password):
            raise forms.ValidationError("The password you entered is incorrect.")
        return password

class ForgottenPasswordEmailForm(forms.Form):
    # Send password reset link to the email
    email = forms.EmailField(max_length=50, label='Email')

    def clean_email(self):
        email_value = self.cleaned_data.get('email').lower()  # Convert to lowercase
        if not User.objects.filter(email=email_value).exists():
            raise ValidationError("This email isn't registered.")
        
        return email_value

class ForgottenPasswordForm(forms.Form):
    new_password = forms.CharField(label="New password", widget=forms.PasswordInput, required=True)
    new_password_confirm = forms.CharField(label="Confirm new password", widget=forms.PasswordInput, required=True)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)

    def clean_new_password(self):
        password_value = self.cleaned_data.get('new_password')

        # Use Django's built-in password validators (password format)
        try:
            validate_password(password_value, self.user)
        except ValidationError as e:
            raise forms.ValidationError(e.messages)

        return password_value

    def clean(self):
        cleaned_data = super().clean()
        new_password_input = cleaned_data.get('new_password')
        new_password_confirm_input = cleaned_data.get('new_password_confirm')

        if new_password_input != new_password_confirm_input:
            raise forms.ValidationError("The new passwords do not match.")

        return cleaned_data

class RecoverAccountForm(forms.ModelForm):
    new_password = forms.CharField(label="New password", widget=forms.PasswordInput, required=True)
    new_password_confirm = forms.CharField(label="Confirm new password", widget=forms.PasswordInput, required=True)

    class Meta:
        model = CustomUser
        fields = ['email']
        labels = {'email': 'Original email'}

    def clean_email(self):
        original_email = self.cleaned_data.get('email').lower()  # Convert to lowercase
        # comparing user's email with original email in db 
        if original_email != self.instance.original_email:
            raise forms.ValidationError("Original email incorrect.")

        return original_email

    def clean_new_password(self):
        password_value = self.cleaned_data.get('new_password')
        try:
            validate_password(password_value, self.instance)
        except ValidationError as e:
            raise forms.ValidationError(e.messages)

        return password_value 

    def clean(self): 
        cleaned_data = super().clean()
        new_password_input = cleaned_data.get('new_password') 
        new_password_confirm_input = cleaned_data.get('new_password_confirm')

        if new_password_input != new_password_confirm_input:
            raise forms.ValidationError("The new passwords do not match.")

        return cleaned_data
