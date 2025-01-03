from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Post(models.Model):
	title = models.CharField(max_length=100)
	text = models.TextField()
	date = models.DateTimeField(auto_now_add=True)
	user = models.ForeignKey(User, on_delete=models.CASCADE)
	# [("this is for model usage", "this is displayed for the user")]
	get_choice = [("PRIVATE", "Private"), ("PUBLIC", "Public")]
	visibility = models.CharField(max_length=50, choices=get_choice, default="PRIVATE")

	def __str__(self):
		return self.title 

