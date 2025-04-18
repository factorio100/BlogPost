from django.contrib import admin
from .models import CustomUser, SignupAttemptEmail, SignupAttemptIpAddress
from django.contrib.auth.admin import UserAdmin

class CustomUserAdmin(UserAdmin):
	model = CustomUser
	list_display = ('username', 'email', 'email_is_verified', 'pending_email', 'date_joined', 'is_active', 'is_staff', 'is_superuser')
	list_filter = ('is_staff', 'is_active', 'is_superuser')
	fieldsets = (
		(None, {'fields': ('username', 'email', 'email_is_verified', 'pending_email', 'password')}),
		('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser')}),
		('Important dates', {'fields': ('last_login', 'date_joined')}),
	)
	readonly_fields = ('date_joined',)
	add_fieldsets = (
		(None, {
        	'classes': ('wide',),
        	'fields': (
        		'username', 'email', 'password1', 'password2', 'is_active', 'is_staff', 'is_superuser')}
		),
	)
	search_fields = ('username',)
	ordering = ('username',)

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(SignupAttemptEmail)
admin.site.register(SignupAttemptIpAddress)


