from django.urls import path, include
from . import views

app_name = 'users'

urlpatterns = [
	path('logout/', views.custom_logout_view, name='logout'),
	path('login/', views.custom_login_view, name='login'),
	path('signup/', views.signup, name='signup'),
	path('verify_email/<uidb64>/<token>/', views.verify_email, name='verify_email'),
	# settings
	path('verify_new_email/<uidb64>/<token>/', views.verify_new_email, name='verify_new_email'),
	path('profile/<int:user_id>/', views.profile, name='profile'),
	path('edit_profile/<int:user_id>/', views.edit_profile, name='edit_profile'),

	path('account/', views.account, name='account'),
	
	path('change_email/', views.change_email, name='change_email'),
	path('cancel_change_email/', views.cancel_change_email, name='cancel_change_email'),

	path('change_password/', views.change_password, name='change_password'),

	path('delete_account/', views.delete_account, name='delete_account'),

	path('forgotten_password_email/', views.forgotten_password_email, name='forgotten_password_email'),
	path('forgotten_password/<uidb64>/<token>/', views.forgotten_password, name='forgotten_password'),

	path('recover_account/<uidb64>/<token>/', views.recover_account, name='recover_account'),
]