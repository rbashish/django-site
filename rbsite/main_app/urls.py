from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from main_app.views import post_detail

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name='home'),
    path('app/', views.app, name='app'),
    path('blog/', views.blog, name='blog'),
    path('project/', views.project, name='project'),
    path('cv/', views.cv, name='cv'),
    path('contact/', views.contact, name='contact'),
    path('register/', views.register, name='register'),
    path('login/', auth_views.LoginView.as_view(), name='login'),  # Keep only this line for login
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('<slug:slug>/', post_detail, name='post_detail'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)