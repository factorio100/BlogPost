from django.urls import path
from . import views

app_name = 'BlogPost'

urlpatterns = [
	path('', views.home, name='home'),
	path('post/<int:post_id>/', views.post, name='post'),
	path('edit_post/<int:post_id>/', views.edit_post, name='edit_post'),
	path('new_post/', views.new_post, name='new_post'),
	path('my_posts/', views.my_posts, name='my_posts'),
]