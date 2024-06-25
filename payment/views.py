from tfn import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import render, redirect
import stripe
from rest_framework import status
from django.http import JsonResponse
from account.models import User
from rest_framework.permissions import IsAuthenticated
from account.renderers import UserRenderer
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.shortcuts import get_object_or_404
import datetime
# This is your test secret API key.

stripe.api_key = settings.STRIPE_SECRET_KEY


class StripeCheckoutView(APIView):
    def post(self, request):
        user_email = request.data.get('email')
        qty = int(request.data.get('qty', 1))

        user = get_object_or_404(User, email=user_email)

        if user.remark:
            print(f"Raw user remark: {user.remark}")
            years = filter_valid_years([year.strip() for year in user.remark.split(',')])
            qty = len(years) - 1 if years else 1
        else:
            qty = 1 

        try:
            checkout_session = stripe.checkout.Session.create(
                customer_email=user_email,
                line_items=[
                    {
                        'price': 'price_1PUjTTGixAyqUicLNUMooAOv',
                        'quantity': qty,
                    },
                ],
                mode='payment',
                success_url=settings.SITE_URL + '?success=true&session_id={CHECKOUT_SESSION_ID}',
                cancel_url=settings.SITE_URL + '?canceled=true',
            )
            return Response({'url': checkout_session.url}, status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error creating Stripe checkout session: {e}")
            return Response(
                {'error':f"Something went wrong when creating stripe payment: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


def filter_valid_years(years):
  return [year for year in years if year.strip()]

class AuthStripeCheckoutView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user  
        qty = int(request.data.get('qty', 1))

        if not user.is_authenticated:
            return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        if user.remark:
            print(f"Raw user remark: {user.remark}")
            years = filter_valid_years([year.strip() for year in user.remark.split(',')])
            
            qty = len(years) - 1 if years else 1
        else:
            qty = 1 

        print(f"Final quantity: {qty}, User remark: {user.remark}")

        try:
            checkout_session = stripe.checkout.Session.create(
                customer_email=user.email,
                line_items=[
                    {
                        'price': 'price_1PUjS3GixAyqUicLvF835GcX',
                        'quantity': qty,
                    },
                ],
                mode='payment',
                success_url=settings.AUTH_SITE_URL + '?success=true&session_id={CHECKOUT_SESSION_ID}',
                cancel_url=settings.AUTH_SITE_URL + '?canceled=true',
            )
            return Response({'url': checkout_session.url}, status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error creating Stripe checkout session: {e}")
            return Response(
                {'error': f"Something went wrong when creating stripe payment: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class StripeWebhookView(APIView):
    def post(self, request):
        payload = request.body.decode('utf-8')
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
        event = None

        if not sig_header:
            return JsonResponse({'error': 'Missing signature header'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
            )
        except ValueError as e:
            return JsonResponse({'error': 'Invalid payload', 'details': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except stripe.error.SignatureVerificationError as e:
            return JsonResponse({'error': 'Invalid signature', 'details': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            user_email = session.get('customer_email')
            payment_amount = session.get('amount_total') / 100  # Amount is in cents
            transaction_id = session.get('payment_intent')
            payment_timestamp = session.get('created')  # Timestamp in seconds since Unix epoch
            payment_date = datetime.datetime.fromtimestamp(payment_timestamp).strftime('%Y-%m-%d %H:%M:%S')
            if user_email:
                try:
                    user = User.objects.get(email=user_email)
                    user.payment_status = 'paid'
                    user.remark = ''
                    user.save()
                    self.send_payment_email(user, payment_amount, transaction_id, payment_date)
                except User.DoesNotExist:
                    return JsonResponse({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        return JsonResponse({'status': 'success'}, status=status.HTTP_200_OK)
    
    def send_payment_email(self, user, payment_amount, transaction_id, payment_date):
            email_subject = "Payment Confirmation"
            message = render_to_string('payment_comfirm.html', {
                'name': user.first_name,
                'amount': payment_amount,
                'transaction_id': transaction_id,
                'payment_date' : payment_date
            })
            email_message = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [user.email],
            )
            email_message.content_subtype = "html"
            email_message.fail_silently = False
            email_message.send()

            return Response({'message': 'Payment confirmation email sent'}, status=status.HTTP_200_OK)