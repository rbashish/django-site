from django.shortcuts import render
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from bs4 import BeautifulSoup

from .models import Post

def home(request):
    return render(request, 'home.html')

def app(request):
    return render(request, 'app.html')

def blog(request):
    posts = Post.objects.all()
    return render(request, 'blog.html', {'posts': posts})

def project(request):
    return render(request, 'project.html')

def cv(request):
    return render(request, 'cv.html')

def contact(request):
    return render(request, 'contact.html')

def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, 'Account created successfully!')
            return redirect('login')
    else:
        form = RegistrationForm()
    return render(request, 'register.html', {'form': form})

def login(request):
    return render(request, 'login.html')

""" def post_detail(request, slug):
    post = Post.objects.get(slug=slug)
    return render(request, 'post_detail.html', {'post':post}) """



def post_detail(request, slug):
    post = Post.objects.get(slug=slug)
    
    # Parse the post content to generate the table of contents
    soup = BeautifulSoup(post.body, 'html.parser')
    headings = soup.find_all(['h2', 'h3'])  # Extract h2 and h3 headings
    toc = [{'text': heading.get_text(), 'id': heading.get('id')} for heading in headings]
    
    return render(request, 'post_detail.html', {'post': post, 'toc': toc})

