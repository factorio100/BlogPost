from django.shortcuts import render, redirect, get_object_or_404
from .models import Post
from .forms import PostForm
from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.db.models import Q
from django.core.mail import send_mail

def check_owner(request, post):
	if post.user != request.user:
		raise Http404

def home(request):
	if request.user.is_authenticated: 
		posts = Post.objects.filter(Q(visibility="PUBLIC") | Q(user=request.user)).order_by('date')

	else:
		posts = Post.objects.filter(visibility="PUBLIC").order_by('date') 

	context = {'posts': posts, 'title': 'home'}
	return render(request, 'BlogPost/home.html', context)

def post(request, post_id):
	post = get_object_or_404(Post, id=post_id)
	context = {'post': post, 'title': 'post'}
	if post.visibility == "PUBLIC":	
		return render(request, 'BlogPost/post.html', context)
	else:
		check_owner(request, post)
		return render(request, 'BlogPost/post.html', context)

@login_required
def edit_post(request, post_id):
	post = get_object_or_404(Post, id=post_id)
	check_owner(request, post)

	if request.method == 'GET':
		form = PostForm(instance=post)
	else:
		form = PostForm(instance=post, data=request.POST)
		if form.is_valid():
			form.save()
			return redirect('BlogPost:post', post_id=post_id)

	context = {'form': form, 'post': post, 'title': 'Edit post'}
	return render(request, 'BlogPost/edit_post.html', context)

@login_required
def new_post(request):
	if request.method == 'GET':
		form = PostForm()
	else:
		form = PostForm(data=request.POST)
		if form.is_valid():
			new_post = form.save(commit=False)
			new_post.user = request.user
			new_post.save()
			return redirect('BlogPost:home')

	context = {'form': form, 'title': 'New post'}
	return render(request, 'BlogPost/new_post.html', context)

@login_required
def my_posts(request):
	my_posts = Post.objects.filter(user=request.user)
	context = {'my_posts': my_posts, 'title': 'My posts'}
	return render(request, 'BlogPost/my_posts.html', context)



