from django.urls import path
from .views import *

urlpatterns = [
    path('create-payment/', StripeCheckoutView.as_view(), name='create-payment'),
    path('authuserpayment/', AuthStripeCheckoutView.as_view(), name='authuserpayment'),
]