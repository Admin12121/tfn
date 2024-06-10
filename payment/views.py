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
# This is your test secret API key.

stripe.api_key = settings.STRIPE_SECRET_KEY


# @app.route('/create-checkout-session', methods=['POST'])
class StripeCheckoutView(APIView):
    def post(self, request):
        user = request.data.get('email')
        try:
            checkout_session = stripe.checkout.Session.create(
                customer_email=user,
                line_items=[
                    {
                        # Provide the exact Price ID (for example, pr_1234) of the product you want to sell
                        'price': 'price_1PQ2HkGixAyqUicL9W28U717',
                        'quantity': 1,
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



class AuthStripeCheckoutView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user  # Assuming the user is authenticated
        if not user.is_authenticated:
            return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            checkout_session = stripe.checkout.Session.create(
                customer_email=user.email,  # Pass user's email to Stripe
                line_items=[
                    {
                        'price': 'price_1PQ2HkGixAyqUicL9W28U717',
                        'quantity': 1,
                    },
                ],
                mode='payment',
                success_url=settings.SITE_URL + '/success?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=settings.SITE_URL + '/cancel',
            )
            return redirect(checkout_session.url, code=303)
        except Exception as e:
            return Response(
                {'error': "Something went wrong when creating stripe payment"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class StripeWebhookView(APIView):
    def post(self, request):
        print('done')
        payload = request.body
        sig_header = request.META['HTTP_STRIPE_SIGNATURE']
        event = None

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
            )
        except ValueError as e:
            # Invalid payload
            return JsonResponse({'error': 'Invalid payload'}, status=status.HTTP_400_BAD_REQUEST)
        except stripe.error.SignatureVerificationError as e:
            # Invalid signature
            return JsonResponse({'error': 'Invalid signature'}, status=status.HTTP_400_BAD_REQUEST)

        # Handle the event
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']

            # Retrieve the user by email
            user_email = session.get('customer_email')
            if user_email:
                try:
                    user = User.objects.get(email=user_email)
                    user.payment_status = 'paid'
                    user.save()
                except User.DoesNotExist:
                    return JsonResponse({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        return JsonResponse({'status': 'success'}, status=status.HTTP_200_OK)