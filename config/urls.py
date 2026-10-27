"""Root URL configuration.

``media/`` is intentionally not served: it holds the ciphertext blobs, which
must only leave the server through the authenticated download endpoint.
"""
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('core.urls')),
]
