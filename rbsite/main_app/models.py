""" from django.db import models

# Create your models here.
class Post(models.Model):
    title = models.CharField(max_length=255)
    slug = models.SlugField()
    intro = models.TextField()
    body = models.TextField()
    tag = models.TextField()
    date_added = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-date_added'] """

from django.db import models
from ckeditor.fields import RichTextField

def default_image_path():
    return 'post_images/blog.png'

class Post(models.Model):
    title = models.CharField(max_length=255)
    slug = models.SlugField()
    intro = models.TextField()
    body = RichTextField()
    tag = models.TextField()
    date_added = models.DateTimeField(auto_now_add=True)
    image = models.ImageField(upload_to='post_images/', default=default_image_path, null=True, blank=True)
    image_alt = models.CharField(max_length=255, blank=True)
   
    class Meta:
        ordering = ['-date_added']

    def __str__(self):
        return self.title
