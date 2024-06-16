from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.contrib.auth import views as auth_views
from account import views as account_views
from django.conf.urls.static import static

urlpatterns = [
    # path('admin/login/', account_views.custom_admin_login, name='custom_admin_login'),
    # path('admin/', admin.site.urls),
    path('user/',include('account.urls')),
    path('',include('payment.urls')),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)