from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

class EmailTokenAuthBackend(BaseBackend):
    def authenticate(self, request, email=None, token=None):
        User = get_user_model()
        try:
            user = User.objects.get(email=email, token=token)
            if user.is_active:
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
