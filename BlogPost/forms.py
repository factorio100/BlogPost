from django import forms
from .models import Post

class PostForm(forms.ModelForm):
	class Meta:
		model = Post
		fields = ['title', 'text', 'visibility']
		labels = {'title': 'Title', 'text': 'Text', 'visibility': 'visibility'}
		widgets = {'text': forms.Textarea(attrs={'cols': 100})}
