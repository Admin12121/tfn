from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import ReferralUser

@receiver(post_save, sender=ReferralUser)
def send_qrcode_email(sender, instance, created, **kwargs):
    if created:
        instance.send_email_with_qrcode()
