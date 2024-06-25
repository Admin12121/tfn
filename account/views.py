import re
import logging
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from tfn import settings
from django.core.mail import EmailMessage
from decouple import config
from django.db.models import Q, Max
from django.shortcuts import get_object_or_404
from .models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from rest_framework.pagination import PageNumberPagination
import json
from django.db import transaction
from django.db.models import Q
from cryptography.fernet import Fernet, InvalidToken
from django.core.files.uploadedfile import InMemoryUploadedFile
from urllib.parse import unquote
from django.http import HttpRequest
from django.shortcuts import render
from django.http import JsonResponse
from django.views import View
from django.core.files.storage import FileSystemStorage
import hashlib
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
from django.utils.dateparse import parse_date

def current_year():
    return datetime.now().year

# Generate Token Manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }
  
from rest_framework.pagination import PageNumberPagination

logger = logging.getLogger(__name__)


class CustomPageNumberPagination(PageNumberPagination):
    def get_page_size(self, request):
        page_size = request.query_params.get('pagedata')
        if page_size:
            try:
                return int(page_size)
            except ValueError:
                pass
        return super().get_page_size(request)

class EmailValidatorView(APIView):
    def post(self, request):
        email = request.data.get('email')
        tfn = request.data.get('tfn')
        abn = request.data.get('abn', None)

        if not email and not tfn:
            return Response({'error': 'Valid email or TFN number is required'}, status=status.HTTP_400_BAD_REQUEST)

        email_exists = User.objects.filter(email=email).exists() if email else False
        tfn_exists = User.objects.filter(tfn=tfn).exists() if tfn else False

        if abn:
            abn_exists = Abn_income.objects.filter(abn=abn).exists()
        else:
            abn_exists = False

        if email_exists or tfn_exists:
            return Response({'error': 'Email or TFN exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        if abn and abn_exists:
            return Response({'error': 'ABN exists'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'Email or TFN doesn\'t exist'}, status=status.HTTP_200_OK)

class CheckEmailView(APIView):
    def post(self, request):
        identifier = request.data.get('email')
        if not identifier:
            return Response({'error': 'Valid Email ot tfn number is required'}, status=status.HTTP_400_BAD_REQUEST)

        email_pattern = r"[^@]+@[^@]+\.[^@]+"
        tfn_pattern = r"^\+?\d{7,15}$"  # Simple pattern for a phone number with optional + and 7-15 digits

        if re.match(email_pattern, identifier):
            lookup_field = 'email'
        elif re.match(tfn_pattern, identifier):
            lookup_field = 'tfn'
        else:
            return Response({'error': 'Enter a valid email or telephone number'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(**{lookup_field: identifier})
        except User.DoesNotExist:
            return Response({'message': 'Email or Tfn doesn\'t exist'}, status=status.HTTP_404_NOT_FOUND)

        if not user.is_active:
            return Response({'message': 'Please verify your email first'}, status=status.HTTP_403_FORBIDDEN)

        if not hasattr(user, 'role') or user.role != 'user':  # Adjust this line based on your role attribute
            return Response({'message': 'Please enter a user email'}, status=status.HTTP_400_BAD_REQUEST)
        
        if user.token:
            user.token = None
            user.save()
        
        token = str(generate_unique_four_digit_number())
        user.token = token
        user.save()

        if user:
            email_subject = "Your One-Time Password (OTP) For a Secure Access"
            message = render_to_string('email_confirmation.html', {
                'name': user.first_name,
                'token': token
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

        return Response({'message': 'Token sent'}, status=status.HTTP_200_OK)
    
class ResendView(APIView):
    def post(self, request):
        email = request.data.get('email')
           
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'message': 'Email or Tfn doesn\'t exist'}, status=status.HTTP_404_NOT_FOUND)

        if not user.is_active:
            return Response({'message': 'Please verify your email first'}, status=status.HTTP_403_FORBIDDEN)

        if user.token:
            user.token = None
            user.save()
        
        token = str(generate_unique_four_digit_number())
        user.token = token
        user.save()

        if user:
            email_subject = "Your One-Time Password (OTP) For a Secure Access"
            message = render_to_string('email_confirmation.html', {
                'name': user.first_name,
                'token': token
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

        return Response({'message': 'Token sent'}, status=status.HTTP_200_OK)
    
class AdminRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, format=None):
        print(request.data)
        try:
            if not request.user.role == 'admin':
                return Response({'error': 'You do not have the authority to proceed.'}, status=status.HTTP_403_FORBIDDEN)
            
            password = request.data['password']
            serializer = AdminRegistrationSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            user = serializer.save()
            
            if request.data['role'] == "referuser":
                try:
                    with transaction.atomic():
                        print(request.data)
                        company = request.data['company_name']
                        company_logo = request.data.get('company_logo', None)
                        isrequired = request.data['isrequired']
                        commissiontype = request.data['commissiontype']
                        commission = request.data['commission']
                        
                        ReferralUser.objects.create(
                            user=user,
                            company=company,
                            company_logo=company_logo,
                            isrequired=isrequired,
                            commissiontype=commissiontype,
                            commission=commission
                        )
                        
                        # Send email only if user role is "referuser"
                        email_subject = "Account Created"
                        message = render_to_string('GlodenUSer.html', {
                            'name': user.first_name,
                            'message': "Your Account has been Created Successfully. This is your Password to login plz reset your password after login. Use your registered email and password to login",
                            'password': password,
                            "commission": commission
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
                except Exception as e:
                    print(f"Exception occurred during referral user creation: {e}")  # Log the exception details
                    transaction.set_rollback(True)
                    return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            return Response({'message': 'Successfully User Created'}, status=status.HTTP_201_CREATED)

        except ValidationError as e:
            error_messages = []
            for field, errors in e.detail.items():
                error_messages.extend(errors)
            print(f"Validation error occurred during user registration: {error_messages}")  # Log the validation error details
            transaction.set_rollback(True)
            return Response({'error': ' '.join(error_messages)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"Exception occurred during user registration: {e}")  # Log the exception details
            transaction.set_rollback(True)
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def decrypt_data(self, encrypted_data):
        key = b'HgtCZxpXZNNC3jylJuWypAuT8UnkJxUjrDGhezgdpZI='
        f = Fernet(key)
        try:
            decoded_data = unquote(encrypted_data)
            decrypted_data = f.decrypt(encrypted_data.encode())
            return decrypted_data.decode()
        except InvalidToken:
            raise ValueError("Invalid encryption token")
    
    def handle_files(self, request):
        passport_files = []
        supporting_documents_files = []
        for key, file in request.FILES.items():
            if key.startswith('passport_drivinglicense'):
                passport_files.append(file)
            elif key.startswith('supportingdocuments'):
                supporting_documents_files.append(file)
        return passport_files, supporting_documents_files
    @transaction.atomic
    def post(self, request, format=None):
        print(request.data)
        try:
            encrypted_data = request.data.get('referral_code')
            referrercode = request.data.get('referercode')
            referraluser_param = request.query_params.get('referraluser', None)
            serializer = UserRegistrationSerializer(data=request.data)

            if serializer.is_valid():
                token = None

                if not referraluser_param:
                    token = str(generate_unique_four_digit_number())
                    serializer.context['token'] = token

                user = serializer.save()
                form_date = FormDate.objects.create(user=user)

                if referraluser_param and 'company' in request.data:
                    company = request.data['company']
                    company_logo = request.data.get('company_logo') 
                    if company_logo: 
                        ReferralUser.objects.create(user=user, company=company, company_logo=company_logo)
                    else:
                        ReferralUser.objects.create(user=user, company=company)
                    user.role = "referuser"
                    user.is_active = False
                    user.save()
                    
                else:
                    logger.info("Processing referral code: %s", referrercode)
                    if encrypted_data:
                        try:
                            decrypted_data = encrypted_data
                            referrercode, refer_user_id = decrypted_data.split(":")
                            form_charge = FormCharge.objects.get(fixed=1)
                            referral_user = ReferralUser.objects.filter(
                                Q(user_id=refer_user_id) | Q(referrercode=referrercode)
                            ).first()
                            if referral_user:
                                if referral_user.commissiontype:
                                    commission_amt = (referral_user.commission / 100.0) * form_charge.amount
                                else:
                                    commission_amt = referral_user.commission
                                ReferalData.objects.create(user=user, referal=referral_user, commissionamt=commission_amt)
                        except Exception as e:
                            print(f"Error in decrypting or processing referral data: {e}")

                    elif referrercode:
                        try:
                            referral_user = ReferralUser.objects.get(referrercode=referrercode)
                            form_charge = FormCharge.objects.get(fixed=1)
                            if referral_user and form_charge:
                                if referral_user.commissiontype:
                                    commission_amt = (referral_user.commission / 100.0) * form_charge.amount
                                else:
                                    commission_amt = referral_user.commission
                                # print("Commision Amount",commission_amt)
                                ReferalData.objects.create(user=user, referal=referral_user, commissionamt=commission_amt)
                                if not referral_user.isrequired:
                                    user.payment_status = "paid"
                                    user.save()
                        except Exception as e :
                            print(f"Error in decrypting or processing referral data: {e}")

                    # Extract nested data from the request
                    abnincome_data = request.data.get('abnincome_data')
                    spouse_data = request.data.get('spouse_data')
                    residentialaddress_data = request.data.get('residentialaddress')
                    bankdetails_data = request.data.get('bankdetails')
                    medicareinformation_data = request.data.get('medicareinformation_data')
                    occupation_data = request.data.get('occupation')
                    additionalinformation_data = {
                        'note': request.data.get('note'),
                    }
                    passport_files, supporting_documents_files = self.handle_files(request)
                    if abnincome_data:
                        abnincome_data = json.loads(abnincome_data)
                        abnincome_data['user'] = user.pk
                        abnincome_serializer = AbnIncomeSerializer(data=abnincome_data)
                        if abnincome_serializer.is_valid():
                            abnincome_serializer.save()
                        else:
                            transaction.set_rollback(True)
                            return Response(abnincome_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                    if spouse_data:
                        spouse_data = json.loads(spouse_data)
                        spouse_data['form_date'] = form_date.pk
                        spouse_serializer = SpouseSerializer(data=spouse_data)
                        if spouse_serializer.is_valid():
                            spouse_serializer.save()
                        else:
                            transaction.set_rollback(True)
                            return Response(spouse_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                    if residentialaddress_data:
                        residentialaddress_data = json.loads(residentialaddress_data)
                        residentialaddress_data['form_date'] = form_date.pk
                        residentialaddress_serializer = ResidentialAddressSerializer(data=residentialaddress_data)
                        if residentialaddress_serializer.is_valid():
                            residentialaddress_serializer.save()
                        else:
                            transaction.set_rollback(True)
                            return Response(residentialaddress_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                    if bankdetails_data:
                        bankdetails_data = json.loads(bankdetails_data)
                        bankdetails_data['form_date'] = form_date.pk
                        bankdetails_serializer = BankDetailsSerializer(data=bankdetails_data)
                        if bankdetails_serializer.is_valid():
                            bankdetails_serializer.save()
                        else:
                            transaction.set_rollback(True)
                            return Response(bankdetails_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                    if medicareinformation_data:
                        medicareinformation_data = json.loads(medicareinformation_data)
                        medicareinformation_data['form_date'] = form_date.pk
                        medicareinformation_serializer = MedicareInformationSerializer(data=medicareinformation_data)
                        if medicareinformation_serializer.is_valid():
                            medicareinformation_serializer.save()
                        else:
                            transaction.set_rollback(True)
                            return Response(medicareinformation_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                    if occupation_data:
                        print(occupation_data)
                        occupation_data = json.loads(occupation_data)
                        applicableincome_data = occupation_data.pop('applicableincome')
                        applicableexpenses_data = occupation_data.pop('applicableexpenses')
                        occupation_data['form_date'] = form_date.pk
                        occupation_serializer = OccupationSerializer(data=occupation_data)
                        if occupation_serializer.is_valid():
                            occupation_instance = occupation_serializer.save()
                            applicableincome_data['occupation'] = occupation_instance
                            applicableexpenses_data['occupation'] = occupation_instance
                            ApplicableIncomeCategories.objects.create(**applicableincome_data)
                            ApplicableExpensesCategories.objects.create(**applicableexpenses_data)
                        else :
                            transaction.set_rollback(True)
                            print(occupation_serializer.errors)
                            return Response(occupation_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                    additional_info_serializer = AdditionalInformationAndDocumentsSerializer(data=additionalinformation_data)
                    additionalinformation_data['form_date'] = form_date.pk
                    if additional_info_serializer.is_valid():
                        additional_info_instance = additional_info_serializer.save()
                        for file in passport_files:
                            Passport_DrivingLicense.objects.create(
                                AddFile=additional_info_instance,
                                passport=file
                            )
                        for file in supporting_documents_files:
                            SupportingDocuents.objects.create(
                                AddFile=additional_info_instance,
                                supportingdocuments=file
                            )
                    else:
                        transaction.set_rollback(True)
                        return Response(additional_info_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                user.is_active = True
                user.save()
                if user:
                    email_subject = "Account Registration complete"
                    if user.role == "user":
                        template = 'message.html'
                    elif user.role == "referuser":
                        template = 'refferuserregisteration.html'
                    
                    message = render_to_string(template, {
                        'name': user.first_name,
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

            else:
                error_messages = []
                for field, errors in serializer.errors.items():
                    for error in errors:
                        error_messages.append(error)
                logger.error("Validation errors: %s", error_messages)
                return Response({"errors": error_messages}, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError as e:
            transaction.set_rollback(True)
            return Response({'error': 'IntegrityError occurred. Transaction rolled back.'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            transaction.set_rollback(True)
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        transaction.set_rollback(True)
        return Response({'message': 'Registration Successful'}, status=status.HTTP_201_CREATED)

class AddDocumentView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def handle_files(self, request):
        passport_files = []
        supporting_documents_files = []
        for key, file in request.FILES.items():
            if key.startswith('passport_drivinglicense'):
                passport_files.append(file)
            elif key.startswith('supportingdocuments'):
                supporting_documents_files.append(file)
        return passport_files, supporting_documents_files

    @transaction.atomic
    def post(self, request, format=None):
        # print(request.data)
        user_id = request.query_params.get('id')
        date = request.data.get('date')
        user = get_object_or_404(User, pk=user_id)

        if FormDate.objects.filter(user=user, year=date).exists():
            return Response({'error': 'A document with this date already exists for the user.'}, status=status.HTTP_400_BAD_REQUEST)
        
        current_year = datetime.now().year
        entered_year = int(date)

        try:
            # Create the FormDate for the current document
            form_date = FormDate.objects.create(user=user, year=entered_year)

            if entered_year == current_year:
                user.status = 'received'
                user.payment_status = 'unpaid'
                user.is_export = False
                user.save()

                if user:
                    email_subject = "Account Registration Successful"
                    message = render_to_string('message.html', {
                        'name': user.first_name,
                        'message': f"Your New Document for {entered_year} has been updated and sent to Supervisor for review. Once your Document is verified, you will be informed through email."
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
            
            # Initialize data from request
            abnincome_data = request.data.get('abnincome_data')
            spouse_data = request.data.get('spouse_data')
            residentialaddress_data = request.data.get('residentialaddress')
            medicareinformation_data = request.data.get('medicareinformation_data')
            occupation_data = request.data.get('occupation')
            additionalinformation_data = {
                'note': request.data.get('note'),
            }

            # Auto-fill bankdetails_data if not provided
            bankdetails_data = request.data.get('bankdetails')
            if not bankdetails_data:
                try:
                    latest_form_date = FormDate.objects.filter(user=user).exclude(id=form_date.pk).latest('year')
                    latest_bank_details = BankDetails.objects.get(form_date=latest_form_date)
                    bankdetails_data = {
                        'etaaccountname': latest_bank_details.etaaccountname,
                        'eftbsbnumber': latest_bank_details.eftbsbnumber,
                        'eftaccountnumber': latest_bank_details.eftaccountnumber,
                        'form_date': form_date.pk
                    }
                    # print(bankdetails_data)
                except ObjectDoesNotExist:
                    bankdetails_data = {
                        'form_date': form_date.pk
                    }

            # Handle file uploads and auto-fill if not provided
            passport_files, supporting_documents_files = self.handle_files(request)

            if not passport_files:
                try:
                    latest_form_date = FormDate.objects.filter(user=user).exclude(id=form_date.pk).latest('year')
                    latest_additional_info = Additionalinformationandsupportingdocuments.objects.get(form_date=latest_form_date)
                    passport_files = Passport_DrivingLicense.objects.filter(AddFile=latest_additional_info).values_list('passport', flat=True)
                except ObjectDoesNotExist:
                    passport_files = []

            # Process and save data
            if abnincome_data:
                abnincome_data = json.loads(abnincome_data)
                abnincome_data['form_date'] = form_date.pk
                abnincome_serializer = AbnIncomeSerializer(data=abnincome_data)
                abnincome_serializer.is_valid(raise_exception=True)
                abnincome_serializer.save()

            if spouse_data:
                spouse_data = json.loads(spouse_data)
                spouse_data['form_date'] = form_date.pk
                spouse_serializer = SpouseSerializer(data=spouse_data)
                spouse_serializer.is_valid(raise_exception=True)
                spouse_serializer.save()

            if residentialaddress_data:
                residentialaddress_data = json.loads(residentialaddress_data)
                residentialaddress_data['form_date'] = form_date.pk
                residentialaddress_serializer = ResidentialAddressSerializer(data=residentialaddress_data)
                residentialaddress_serializer.is_valid(raise_exception=True)
                residentialaddress_serializer.save()

            if bankdetails_data:
                if isinstance(bankdetails_data, str):
                    bankdetails_data = json.loads(bankdetails_data)
                bankdetails_data['form_date'] = form_date.pk
                bankdetails_serializer = BankDetailsSerializer(data=bankdetails_data)
                bankdetails_serializer.is_valid(raise_exception=True)
                bankdetails_serializer.save()

            if medicareinformation_data:
                medicareinformation_data = json.loads(medicareinformation_data)
                medicareinformation_data['form_date'] = form_date.pk
                medicareinformation_serializer = MedicareInformationSerializer(data=medicareinformation_data)
                medicareinformation_serializer.is_valid(raise_exception=True)
                medicareinformation_serializer.save()

            if occupation_data:
                occupation_data = json.loads(occupation_data)
                applicableincome_data = occupation_data.pop('applicableincome')
                applicableexpenses_data = occupation_data.pop('applicableexpenses')
                occupation_data['form_date'] = form_date.pk
                occupation_serializer = OccupationSerializer(data=occupation_data)
                if occupation_serializer.is_valid():
                    occupation_instance = occupation_serializer.save()
                    ApplicableIncomeCategories.objects.create(occupation=occupation_instance, **applicableincome_data)
                    ApplicableExpensesCategories.objects.create(occupation=occupation_instance, **applicableexpenses_data)
                # else:
                #     return Response(occupation_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            additionalinformation_data['form_date'] = form_date.pk
            additional_info_serializer = AdditionalInformationAndDocumentsSerializer(data=additionalinformation_data)
            if additional_info_serializer.is_valid():
                additional_info_instance = additional_info_serializer.save()

                # Use existing passport_files if not provided
                if request.FILES.getlist('passport_drivinglicense'):
                    for file in passport_files:
                        Passport_DrivingLicense.objects.create(
                            AddFile=additional_info_instance,
                            passport=file  # Use the file object directly
                        )
                else:
                    for passport_file in passport_files:
                        Passport_DrivingLicense.objects.create(
                            AddFile=additional_info_instance,
                            passport=passport_file  # Use the stored file path
                        )
                
                # Save supporting documents only if provided
                for file in supporting_documents_files:
                    SupportingDocuents.objects.create(
                        AddFile=additional_info_instance,
                        supportingdocuments=file
                    )
            else:
                return Response(additional_info_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'message': 'Document Added Successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            transaction.set_rollback(True)
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
                
class UserActivationView(APIView):
    def post(self, request, format=None):
        try:
            email = request.data.get('email')
            token = request.data.get('token')
            myuser = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
            
        if not myuser.token:
            return Response({'error': 'Token is expired or invalid.'}, status=status.HTTP_400_BAD_REQUEST)
        
        if myuser is not None and myuser.token == token:
            myuser.is_active = True
            myuser.token = None
            myuser.save()
            return Response({'message': 'Your account has been activated successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Activation link is invalid or expired.'}, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    
    def post(self, request, format=None):
        email_or_tfn = request.data.get('email')
        token = request.data.get('otp')

        # Check if the input is an email
        if '@' in email_or_tfn:
            kwargs = {'email': email_or_tfn}
        else:
            kwargs = {'tfn': email_or_tfn}

        try:
            # Retrieve the user by email or username
            user = User.objects.get(**kwargs)
        except User.DoesNotExist:
            return Response({'errors': {'user': ["User doesn't exist! Please register with a valid email or username"]}}, status=status.HTTP_404_NOT_FOUND)
        
        if user.role != 'user':
            return Response({'errors': {'role': ["Please use the other portal to login."]}}, status=status.HTTP_403_FORBIDDEN)

        if not user.token:
            return Response({'errors': {'token': ["Invalid or expired token."]}}, status=status.HTTP_400_BAD_REQUEST)

        if user.token == token:
            user.token = None
            user.save()
            auth_token = get_tokens_for_user(user)
            return Response({'token': auth_token,'role': user.role, 'message': 'Login success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors': {'non_field_errors': ["Credentials don't match"]}}, status=status.HTTP_400_BAD_REQUEST)

class AbNormalUser(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            user = User.objects.get(email = email)
        except User.DoesNotExist:
            return Response({'errors': {'user': ["User doesn't exist! Please register with a valid email or username"]}}, status=status.HTTP_404_NOT_FOUND)

        if user.is_active:
            user = authenticate(request, email=email, password=password)
            if user is not None: 
                if user.role == 'user':
                    return Response({'errors': {'role': ["User is not allowed to login through this portal"]}}, status=status.HTTP_403_FORBIDDEN)
                # token = get_tokens_for_user(user)
                # return Response({'token': token, 'role': user.role, 'msg': 'Login Success'}, status=status.HTTP_200_OK)
                if user.token:
                    user.token = None
                    user.save()
                
                token = str(generate_unique_four_digit_number())
                user.token = token
                user.save()

                if user:
                    email_subject = "Your One-Time Password (OTP) For a Secure Access"
                    message = render_to_string('email_confirmation.html', {
                        'name': user.first_name,
                        'token': token
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
                return Response({'message': 'Token sent'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'non_field_errors': ["Password doesn't match"]}}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'errors': {'user': ["Your Accoutn is Not Active "]}}, status=status.HTTP_404_NOT_FOUND)

class TwoFaView(APIView):
    renderer_classes = [UserRenderer]
   
    def post(self, request, format=None):
        email_or_tfn = request.data.get('email')
        token = request.data.get('otp')

        try:
            user = User.objects.get(email = email_or_tfn)
        except User.DoesNotExist:
            return Response({'errors': {'user': ["User doesn't exist! Please register with a valid email or username"]}}, status=status.HTTP_404_NOT_FOUND)
        
        if not user.token:
            return Response({'errors': {'token': ["Invalid or expired token."]}}, status=status.HTTP_400_BAD_REQUEST)

        if user.token == token:
            user.token = None
            user.save()
            auth_token = get_tokens_for_user(user)
            return Response({'token': auth_token,'role': user.role, 'message': 'Login success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors': {'non_field_errors': ["Credentials don't match"]}}, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, format=None):
        user = request.user
        year_param = request.query_params.get('year', datetime.now().year)
        if user.role == "user":
            serializer = UserDataSerializer(user, context={'request': request, 'year': year_param})
            return Response(serializer.data, status=status.HTTP_200_OK)
        elif user.role == "referuser":
            serializer = RefUserDataSerializer(user, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)
        elif user.role == "admin" or user.role == "staff":
            serializer = AdminandStaffUserDataSerializer(user, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Some thing went wrong user does not exist"}, status=status.HTTP_404_NOT_FOUND)

class AllUsersView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPageNumberPagination

    def get(self, request, format=None):

        user = request.user
        if user.role == "user":
            # Mimic redirection to UserProfileView
            user_profile_view = UserProfileView()
            response = user_profile_view.get(request)
            return response

        users = User.objects.all()

        if request.user.role == 'staff':
            users = users.exclude(role='admin')

        role_param = request.query_params.get('role')
        paymentstatus_param = request.query_params.get('paymentstatus')
        refdata_param = request.query_params.get('refdata')
        refstatus_param = request.query_params.get('refstatus')
        name_param = request.query_params.get('search')
        is_active_param = request.query_params.get('is_active')
        status_param = request.query_params.get('status')
        id_param = request.query_params.get('id')
        year_param = request.query_params.get('year')
        from_param = request.query_params.get('from')
        to_param = request.query_params.get('to')
        from_param = request.query_params.get('from')
        to_param = request.query_params.get('to')

        # Parse the 'from' date
        if from_param:
            try:
                from_date = datetime.strptime(from_param, '%d/%m/%Y').date()
                users = users.filter(created_at__gte=from_date)
            except ValueError:
                return Response({'detail': 'Invalid from date format.'}, status=status.HTTP_400_BAD_REQUEST)

        # Parse the 'to' date
        if to_param:
            try:
                to_date = datetime.strptime(to_param, '%d/%m/%Y').date()
                users = users.filter(created_at__lte=to_date)
            except ValueError:
                return Response({'detail': 'Invalid to date format.'}, status=status.HTTP_400_BAD_REQUEST)

        if id_param:
            try:
                user = users.get(id=id_param)
                if user.role == 'referuser':
                    serializer = RefUserDataSerializer(user, context={'request': request})
                elif user.role in ['admin', 'staff']:
                    serializer = AdminandStaffUserDataSerializer(user, context={'request': request})
                else:
                    serializer = UserDataSerializer(user, context={'request': request})
                return Response(serializer.data)
            except User.DoesNotExist:
                return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        if name_param:
            users = users.filter(
                Q(email__icontains=name_param) |
                Q(first_name__icontains=name_param) |
                Q(middle_name__icontains=name_param) |
                Q(last_name__icontains=name_param) |
                Q(phone__icontains=name_param) |
                Q(tfn__icontains = name_param)
            )

        if paymentstatus_param:
            users = users.filter(payment_status=paymentstatus_param)

        if refdata_param:
            try:
                user = User.objects.get(id=refdata_param)
                ref_data = ReferralUser.objects.get(user=user)
                if refstatus_param:
                    ref_user_data = ReferalData.objects.filter(referal=ref_data, status=refstatus_param)
                else:
                    ref_user_data = ReferalData.objects.filter(referal=ref_data)
                user_ids = ref_user_data.values_list('user_id', flat=True)
                users = users.filter(id__in=user_ids)
            except (User.DoesNotExist, ReferralUser.DoesNotExist):
                users = User.objects.none()

        if is_active_param:
            users = users.filter(is_active=is_active_param.lower() == 'true')

        if status_param:
            users = users.filter(status=status_param)

        if role_param:
            users = users.filter(role=role_param)

        if role_param == 'user':
            if year_param:
                users = users.filter(formdata__year=year_param)
            else:
                users = self.get_users_with_latest_formdate(users)

        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(users, request)

        if role_param == 'referuser':
            serializer = RefUserDataSerializer(result_page, many=True, context={'request': request})
        elif role_param in ['admin', 'staff']:
            serializer = AdminandStaffUserDataSerializer(result_page, many=True, context={'request': request})
        else:
            serializer = UserDataSerializer(result_page, many=True, context={'request': request})

        return paginator.get_paginated_response(serializer.data)

    def get_serializer_context(self):
        return {'request': self.request}

    def get_users_with_latest_formdate(self, users):
        latest_formdates = FormDate.objects.filter(user__in=users).values('user').annotate(latest_date=Max('year'))
        user_ids = [entry['user'] for entry in latest_formdates]
        users = users.filter(id__in=user_ids)
        return users
        
    def patch(self, request, format=None):
        if request.user.role not in ['admin', 'staff', 'user']:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
        user_param = request.query_params.get('id')
        year_param = request.query_params.get('year')
        role_param = request.query_params.get('role')
        medicareinformation_param = request.query_params.get('medicareinformation')
        residentialaddress_param = request.query_params.get('residentialaddress')
        bankdetails_param = request.query_params.get('bankdetails')
        occupation_param = request.query_params.get('occupation')
        additionalinformation_param = request.query_params.get('additionalinformation')

        if not user_param:
            return Response({'detail': 'User ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_param)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        if user_param and role_param in ["admin", "staff"]:
            serializer = AdminandStaffUserDataSerializer(user, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response({'detail': 'Invalid role or request data'}, status=status.HTTP_400_BAD_REQUEST)
        elif user_param and role_param == "referuser":
            serializer = AdminandStaffUserDataSerializer(user, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                with transaction.atomic():
                    serializer.save()

                    try:
                        referral_user = user.referuser

                        referral_user.company = request.data.get('company_name', referral_user.company)
                        referral_user.isrequired = self.parse_boolean(request.data.get('isrequired', referral_user.isrequired))
                        referral_user.commissiontype = self.parse_boolean(request.data.get('commissiontype', referral_user.commissiontype))
                        referral_user.commission = request.data.get('commission', referral_user.commission)
                        company_logo = request.data.get('company_logo')
                        if company_logo and isinstance(company_logo, InMemoryUploadedFile):
                            referral_user.company_logo = company_logo

                        referral_user.save()

                    except ReferralUser.DoesNotExist:
                        return Response({'detail': 'ReferralUser not found.'}, status=status.HTTP_400_BAD_REQUEST)
                    except Exception as e:
                        return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

                return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            if request.user.role in ['admin','user'] and user.role == 'user':
                # print(request.data)
                try:
                    if not year_param:
                        if 'abnincome' in request.data and request.data['abnincome'] == 'false':
                            user.abn = False
                            user.save()
                            try:
                                abn_income = user.abn_income
                                abn_income.delete()
                            except Abn_income.DoesNotExist:
                                pass
                        serializer = UserUpdateSerializer(user, data=request.data, partial=True)
                        if serializer.is_valid(raise_exception=True):
                            serializer.save()
                        try:
                            spouse_data = request.data.get('spouse_data')
                            abnincome_data = request.data.get('abnincome_data')

                            if abnincome_data:
                                abnincome_data = json.loads(abnincome_data)
                                abn_id = abnincome_data.get('id', None)

                                if abn_id: 
                                    try:
                                        abnincome = Abn_income.objects.get(id=abn_id)
                                        abnincome_serializer = AbnIncomeSerializer(abnincome, data=abnincome_data, partial=True)
                                        if abnincome_serializer.is_valid(raise_exception=True):
                                            abnincome_serializer.save()
                                    except Abn_income.DoesNotExist:
                                        return Response({'detail': 'ABN income not found.'}, status=status.HTTP_404_NOT_FOUND)
                                else:
                                    abnincome_data['user'] = user.pk  # Assuming user is available in the context
                                    abnincome_serializer = AbnIncomeSerializer(data=abnincome_data)
                                    if abnincome_serializer.is_valid(raise_exception=True):
                                        abnincome_serializer.save()

                            if spouse_data:
                                # print("done")
                                spouse_data = json.loads(spouse_data)
                                spouse_id = spouse_data.get('id')
                                year = spouse_data.get('year')
                                form_date = FormDate.objects.get(user=user, year=year)

                                if spouse_id:
                                    # print("done again")
                                    try:
                                        spouse = Spouse.objects.get(id=spouse_id)
                                        spouse_serializer = SpouseSerializer(spouse, data=spouse_data, partial=True)
                                        if spouse_serializer.is_valid(raise_exception=True):
                                            spouse_serializer.save()
                                    except Spouse.DoesNotExist:
                                        return Response({'detail': 'Spouse not found.'}, status=status.HTTP_404_NOT_FOUND)
                                else:
                                    # print("done dome again")
                                    spouse_data['form_date'] = form_date.pk
                                    spouse_serializer = SpouseSerializer(data=spouse_data)
                                    if spouse_serializer.is_valid(raise_exception=True):
                                        spouse_serializer.save()
                                return Response({'detail': 'Spouse data processed successfully.'}, status=status.HTTP_200_OK)
                            return Response({'detail': 'User data updated successfully.'}, status=status.HTTP_200_OK)
                        except (Abn_income.DoesNotExist, Spouse.DoesNotExist):
                            return Response({'detail': 'ABN income or spouse data not found.'}, status=status.HTTP_404_NOT_FOUND)                        
                    else:
                        form_date = FormDate.objects.get(user=user, year=year_param)
                except FormDate.DoesNotExist:
                    return Response({'detail': 'Form date not found for the specified year.'}, status=status.HTTP_404_NOT_FOUND)

                if medicareinformation_param:
                    try:
                        medicareinformation = MedicareInformation.objects.get(form_date=form_date, id=medicareinformation_param)
                        serializer = MedicareInformationSerializer(medicareinformation, data=request.data, partial=True)
                        if serializer.is_valid(raise_exception=True):
                            serializer.save()
                            return Response({'detail': f'MedicareInformation data for {user.first_name} updated successfully.'}, status=status.HTTP_200_OK)
                    except MedicareInformation.DoesNotExist:
                        return Response({'detail': 'Medicare information not found.'}, status=status.HTTP_404_NOT_FOUND)
                elif residentialaddress_param:
                    try:
                        residentialaddress = Residential_addresh.objects.get(form_date=form_date, id=residentialaddress_param)
                        serializer = ResidentialAddressSerializer(residentialaddress, data=request.data, partial=True)
                        if serializer.is_valid(raise_exception=True):
                            serializer.save()
                            return Response({'detail': f'Residential Address data for {user.first_name} updated successfully.'}, status=status.HTTP_200_OK)
                    except Residential_addresh.DoesNotExist:
                        return Response({'detail': 'Residential address not found.'}, status=status.HTTP_404_NOT_FOUND)
                elif bankdetails_param:
                    try:
                        bankdetails = BankDetails.objects.get(form_date=form_date, id=bankdetails_param)
                        serializer = BankDetailsSerializer(bankdetails, data=request.data, partial=True)
                        if serializer.is_valid(raise_exception=True):
                            serializer.save()
                            return Response({'detail': f'Bank details data for {user.first_name} updated successfully.'}, status=status.HTTP_200_OK)
                    except BankDetails.DoesNotExist:
                        return Response({'detail': 'Bank details not found.'}, status=status.HTTP_404_NOT_FOUND)
                elif occupation_param:
                    try:
                        applicableincome_data = request.data.get('applicableincome')
                        applicableexpenses_data = request.data.get('applicableexpenses')
                        occupation = Occupation.objects.get(form_date=form_date, id=occupation_param)
                        serializer = OccupationSerializer(occupation, data=request.data, partial=True)
                        if serializer.is_valid(raise_exception=True):
                            if applicableincome_data:
                                applicableincome = ApplicableIncomeCategories(occupation=occupation, id=applicableincome_data.get('id'))
                                applicableincome_serializer = ApplicableIncomeCategoriesSerializer(applicableincome, data=applicableincome_data, partial=True)
                                if applicableincome_serializer.is_valid(raise_exception=True):
                                    applicableincome_serializer.save()

                            if applicableexpenses_data:
                                applicableexpenses = ApplicableExpensesCategories(occupation=occupation, id=applicableexpenses_data.get('id'))
                                applicableexpenses_serializer = ApplicableExpensesCategoriesSerializer(applicableexpenses, data=applicableexpenses_data, partial=True)
                                if applicableexpenses_serializer.is_valid(raise_exception=True):
                                    applicableexpenses_serializer.save()

                            serializer.save()
                            return Response({'detail': f'Occupation data for {user.first_name} updated successfully.'}, status=status.HTTP_200_OK)
                    except Occupation.DoesNotExist:
                        return Response({'detail': 'Occupation not found.'}, status=status.HTTP_404_NOT_FOUND)
                elif additionalinformation_param:
                    try:
                        additionalinformation = Additionalinformationandsupportingdocuments.objects.get(form_date=form_date, id=additionalinformation_param)
                        serializer = AdditionalInformationAndDocumentsSerializer(additionalinformation, data=request.data, partial=True)
                        if serializer.is_valid(raise_exception=True):
                            serializer.save()
                            return Response({'detail': f'Additional information for {user.first_name} updated successfully.'}, status=status.HTTP_200_OK)
                    except Additionalinformationandsupportingdocuments.DoesNotExist:
                        return Response({'detail': 'Additional information not found.'}, status=status.HTTP_404_NOT_FOUND)

            elif request.user.role == 'staff' and user.role == 'user':
                if 'status' in request.data:
                    user.status = request.data['status']
                    user.save()
                    return Response({'detail': 'User status updated successfully.'}, status=status.HTTP_200_OK)
                else:
                    return Response({'detail': 'Staff can only update the status field.'}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, format=None):
        user_param = request.query_params.get('id')
        formdate_param = request.query_params.get('formdateid')
        
        if not user_param and not formdate_param:
            return Response({'error': 'Either User ID or FormDate ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        if user_param and formdate_param:
            try:
                user = User.objects.get(id=user_param)
                formdate_instance = FormDate.objects.get(id=formdate_param, user=user)

                if request.user.role != 'admin':
                    return Response({'error': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

                # Check if deleting this FormDate would leave no other FormDate for the user
                other_formdates_count = FormDate.objects.filter(user=user).exclude(id=formdate_param).count()
                if other_formdates_count == 0:
                    return Response({'error': 'Cannot delete all FormDate data. At least one FormDate must exist for the user.'}, status=status.HTTP_400_BAD_REQUEST)
                
                formdate_instance.delete()
                user.delete()
                return Response({'message': 'User and related FormDate deleted successfully.'}, status=status.HTTP_200_OK)
                
            except User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
            except FormDate.DoesNotExist:
                return Response({'error': 'FormDate not found for the specified user.'}, status=status.HTTP_404_NOT_FOUND)

        if user_param:
            try:
                user = User.objects.get(id=user_param)
                if request.user.role == 'user':
                    if FormDate.objects.filter(user=user).exists():
                        user.delete()
                        return Response({'message': 'User deleted successfully.'}, status=status.HTTP_200_OK)
                    else:
                        return Response({'error': 'Cannot delete user. No FormDate data exists for the user.'}, status=status.HTTP_400_BAD_REQUEST)
                else:  # This is the admin case
                    user.delete()
                    return Response({'message': 'User deleted successfully.'}, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        if formdate_param:
            try:
                formdate_instance = FormDate.objects.get(id=formdate_param)
                user = formdate_instance.user
                if request.user.role != 'admin':
                    return Response({'error': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
                
                # Check if deleting this FormDate would leave no other FormDate for the user
                other_formdates_count = FormDate.objects.filter(user=user).exclude(id=formdate_param).count()
                if other_formdates_count == 0:
                    return Response({'error': 'Cannot delete all FormDate data. At least one FormDate must exist for the user.'}, status=status.HTTP_400_BAD_REQUEST)

                formdate_instance.delete()
                return Response({'message': 'FormDate deleted successfully.'}, status=status.HTTP_200_OK)
                
            except FormDate.DoesNotExist:
                return Response({'error': 'FormDate not found.'}, status=status.HTTP_404_NOT_FOUND)
    
    def parse_boolean(self, value):
        if isinstance(value, str):
            return value.lower() in ('true', '1')
        return bool(value)

class ClientuserStatusUpdates(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def patch(self, request, format=None):
        # print(request.data)

        if request.user.role not in ['admin', 'staff']:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

        user_ids = request.data.get('user')
        new_status = request.data.get('status')
        new_payment_status = request.data.get('paymentstatus')

        if not user_ids:
            return Response({'detail': 'User IDs are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if at least one of new_status or new_payment_status is provided
        if not (new_status or new_payment_status):
            return Response({'detail': 'At least one of status or payment status is required.'}, status=status.HTTP_400_BAD_REQUEST)


        # Parse user_ids from JSON string
        if isinstance(user_ids, str):
            try:
                user_ids = json.loads(user_ids)
            except json.JSONDecodeError:
                return Response({'detail': 'User IDs format is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

        # Convert user_ids elements to integers if they are strings
        try:
            user_ids = [int(uid) for uid in user_ids]
        except ValueError:
            return Response({'detail': 'User IDs must be a list of integers.'}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure user_ids is a list of integers
        if not isinstance(user_ids, list) or not all(isinstance(uid, int) for uid in user_ids):
            return Response({'detail': 'User IDs must be a list of integers.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                if new_payment_status:
                    User.objects.filter(id__in=user_ids).update(payment_status=new_payment_status)
                else:
                    User.objects.filter(id__in=user_ids).update(status=new_status)

                users = User.objects.filter(id__in=user_ids)

                if new_status == 'dormat':
                    self.send_dormant_status_emails(users)

                # Update ReferalData status if user exists and meets criteria
                for user in users:
                    if user.status == 'lodgedwithato' and user.payment_status == 'paid':
                        ReferalData.objects.filter(user=user, status='not due').update(status='payable')

            return Response({'detail': 'Users updated successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

    def send_dormant_status_emails(self, users):
        email_subject = "Your account status has been updated"
        for user in users:
            if user.status == 'dormat':
                message = render_to_string('documentverified.html', {
                    'name': user.first_name,
                    'message': 'Your Account has been Verified'
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

class RefUserData(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPageNumberPagination

    def get(self, request, format=None):
        if request.user.role not in ['admin', 'staff', 'referuser']:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

        data = ReferalData.objects.all()
        id = request.data.get('id')

        if request.user.role == 'admin' or request.user.role == 'staff':
            if(id):
                user = User.object.get_object_or_404(id=id)
                data = data.filter(referal__user=user)
            else:
                data = data
        elif request.user.role == 'referuser':
            data = data.filter(referal__user=request.user)

        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(data, request)
        serializer = ReferalDataSerializer(result_page, many=True, context={'request': request})

        return paginator.get_paginated_response(serializer.data)
        
class RefDataStatusUpdates(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def patch(self, request, format=None):
        if request.user.role not in ['admin']:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

        user_ids = request.data.get('user')
        new_status = request.data.get('status')
        new_date = request.data.get('date')

        if not user_ids or not new_status:
            return Response({'detail': 'User IDs and status are required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Parse user_ids from JSON string
        if isinstance(user_ids, str):
            try:
                user_ids = json.loads(user_ids)
            except json.JSONDecodeError:
                return Response({'detail': 'User IDs format is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

        # Convert user_ids elements to integers if they are strings
        try:
            user_ids = [int(uid) for uid in user_ids]
        except ValueError:
            return Response({'detail': 'User IDs must be a list of integers.'}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure user_ids is a list of integers
        if not isinstance(user_ids, list) or not all(isinstance(uid, int) for uid in user_ids):
            return Response({'detail': 'User IDs must be a list of integers.'}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure status is a string
        if not isinstance(new_status, str):
            return Response({'detail': 'Status must be a string.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                # Fetch the User instances
                users = User.objects.filter(id__in=user_ids)
                if not users.exists():
                    return Response({'detail': 'No matching users found.'}, status=status.HTTP_404_NOT_FOUND)

                # Fetch the referral data instances
                referal_data_instances = ReferalData.objects.filter(user__in=users)
                if not referal_data_instances.exists():
                    return Response({'detail': 'No matching referral data found.'}, status=status.HTTP_404_NOT_FOUND)

                referral_user = referal_data_instances.first().referal
                if not referral_user:
                    return Response({'detail': 'Referral user not found.'}, status=status.HTTP_404_NOT_FOUND)

                # Update the status and settled date of ReferalData
                referal_data_instances.update(status=new_status, settleddate=new_date)

                # Sum the commission amounts
                total_commission_amt = referal_data_instances.aggregate(total_commission=models.Sum('commissionamt'))['total_commission']
                settled_amount = total_commission_amt if total_commission_amt else 0

                # Create ReferalSettlement record
                settlement = ReferalSettlement.objects.create(
                    refuser=referral_user,
                    settledamount=settled_amount,
                    settleddate=new_date
                )
                settlement.user.set(referal_data_instances)  # Associate referral data instances with the settlement

            return Response({'detail': 'Users updated and settlements created successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ReferalSettlementListView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    pagination_class = CustomPageNumberPagination

    def get(self, request, format=None):
        if request.user.role not in ['admin', 'staff', 'referuser']:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

        data = ReferalSettlement.objects.all()
        paginator = self.pagination_class()
        result_page = paginator.paginate_queryset(data, request)
        serializer = ReferalSettlementSerializer(result_page, many=True, context={'request': request})
        return paginator.get_paginated_response(serializer.data)

class FormChargeView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        if request.user.role not in ['admin']:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
        
        form_charge = FormCharge.objects.all()
        if not form_charge.exists():
            return Response({'detail': 'No FormCharge data found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = FormChargeSerializer(form_charge, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def patch(self, request, format=None):
        if request.user.role not in ['admin']:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)
        data_param = FormCharge.objects.get(fixed=1)
        serializer = FormChargeSerializer(data_param , data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({'detail': 'Invalid role or request data'}, status=status.HTTP_400_BAD_REQUEST)
    
class DataExported(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def patch(self, request, format=None):
        if request.user.role not in ['admin']:
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

        user_ids = request.data.get('user')

        # Parse user_ids from JSON string
        if isinstance(user_ids, str):
            try:
                user_ids = json.loads(user_ids)
            except json.JSONDecodeError:
                return Response({'detail': 'User IDs format is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

        # Convert user_ids elements to integers if they are strings
        try:
            user_ids = [int(uid) for uid in user_ids]
        except ValueError:
            return Response({'detail': 'User IDs must be a list of integers.'}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure user_ids is a list of integers
        if not isinstance(user_ids, list) or not all(isinstance(uid, int) for uid in user_ids):
            return Response({'detail': 'User IDs must be a list of integers.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                # Fetch the User instances
                users = User.objects.filter(id__in=user_ids)
                if not users.exists():
                    return Response({'detail': 'No matching users found.'}, status=status.HTTP_404_NOT_FOUND)
                users.update(is_export=True)
            return Response({'detail': 'Data Exported successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class SendUserPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = SendUserPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]

  def post(self, request, format=None):
    serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class AdminChangePasswordView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]

  def post(self, request, format=None):
    id = request.data.get('id')
    user = User.objects.get(id=id)
    password = request.data.get('password')
    email = user.email
    serializer = UserChangePasswordSerializer(data=request.data, context={'user':user})
    serializer.is_valid(raise_exception=True)
    if user:
        email_subject = "Password changed"
        message = render_to_string('message.html', {
            'name': user.first_name,
            'password' : password,
            'message' : "Your Password has been changed by Admin"
        })
        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email],
        )
        email_message.content_subtype = "html"
        email_message.fail_silently = False
        email_message.send()
    return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class ImportUserDataView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        file = request.FILES.get('file')
        if not file:
            return JsonResponse({'error': 'No file provided'}, status=400)

        file_hash = self.compute_file_hash(file)

        if ImportedFile.objects.filter(file_hash=file_hash).exists():
            return JsonResponse({'error': 'This file has already been uploaded'}, status=400)

        fs = FileSystemStorage()
        filename = fs.save(file.name, file)
        file_path = fs.path(filename)

        try:
            self.check_for_existing_users(file_path, file.name)
        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)

        try:
            with transaction.atomic():
                self.import_data(file_path, file.name)
                ImportedFile.objects.create(file_name=file.name, file_hash=file_hash)
                return JsonResponse({'success': 'Data imported successfully'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    def compute_file_hash(self, file):
        hash_md5 = hashlib.md5()
        for chunk in file.chunks():
            hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def check_for_existing_users(self, file_path, file_name):
        df = pd.read_excel(file_path) if file_name.endswith('.xlsx') else pd.read_csv(file_path)
        existing_emails = User.objects.filter(email__in=df['Email']).values_list('email', flat=True)
        if existing_emails:
            raise ValueError(f"The following users already exist: {', '.join(existing_emails)}")

    def import_data(self, file_path, file_name):
        df = pd.read_excel(file_path) if file_name.endswith('.xlsx') else pd.read_csv(file_path)
        required_fields = [
            'Email', 'First Name', 'Last Name', 'Residential Address Line 1', 
            'Residential Address State', 'EFT Account Name', 'EFT BSB Number', 
            'EFT Account Number', 'Year', 'Birth Date'
        ]
        detailed_errors = []

        for index, row in df.iterrows():
            missing_fields = [field for field in required_fields if pd.isna(row.get(field))]
            if missing_fields:
                detailed_errors.append(f"Row {index + 1}: Missing required fields: {', '.join(missing_fields)}")
                continue

            birth_date = row['Birth Date']
            if isinstance(birth_date, str):
                birth_date = datetime.strptime(birth_date, '%d/%m/%Y').date()
            elif isinstance(birth_date, datetime):
                birth_date = birth_date.date()
            else:
                birth_date = None

            if birth_date is not None:
                birth_date = birth_date.strftime('%d/%m/%Y')

            middle_name = row.get('Middle Name', '')
            middle_name = '' if pd.isna(middle_name) else middle_name
            phone = self.clean_phone_number(row.get('Phone', ''))
            user_data = {
                'email': row.get('Email'),
                'title': row.get('Title', ''),
                'first_name': row.get('First Name'),
                'middle_name': middle_name,
                'last_name': row.get('Last Name'),
                'phone': phone,
                'dateofbirth': birth_date,
                'numberofdependents': row.get('Number of Dependents', 0),
                'tfn': row.get('TFN', ''),
                'gender': row.get('Gender', ''),
                'abn': bool(row.get('ABN')),
                'spouse': bool(row.get('Spouse')),
                'medicareinformation': bool(row.get('Medicare Information')),
            }

            try:
                # print(f"User data after saving: {user_data}")   
                user = User.objects.create(**user_data)
                # print(f"User data after saving: {user}")
                formdate, _ = FormDate.objects.get_or_create(user=user, year=row.get('Year'))
                self.import_nested_data(formdate, user, row)
            except IntegrityError as e:
                detailed_errors.append(f"Row {index + 1}: Error importing user {row['Email']}: {str(e)}")
            except Exception as e:
                detailed_errors.append(f"Row {index + 1}: Unexpected error: {str(e)}")

        if detailed_errors:
            error_message = '\n'.join(detailed_errors)
            raise ValueError(f"Errors occurred during import:\n{error_message}")

    def clean_phone_number(self, phone):
        phone = str(phone)
        if phone.startswith('61'):
            return phone[2:]
        return phone


    def import_nested_data(self, formdate, user, row):
        if pd.notna(row.get('ABN')):
            Abn_income.objects.update_or_create(
                user=user,
                defaults={
                    'abn': row.get('ABN'),
                    'natureofworkdone': row.get('Nature of Work Done', ''),
                    'grossincomereceivedinbank': row.get('Gross Income Received in Bank', None)
                }
            )

        if pd.notna(row.get('Spouse First Name')):
            Spouse.objects.update_or_create(
                form_date=formdate,
                defaults={
                    'first_name': row.get('Spouse First Name'),
                    'middle_name': row.get('Spouse Middle Name', ''),
                    'last_name': row.get('Spouse Last Name'),
                    'spouse_taxable_income': row.get('Spouse Taxable Income', None),
                    'dob': row.get('Spouse DOB', '')
                }
            )
        residential_addresh = row.get('Residential Address Line 2', '')
        residential_addresh = '' if pd.isna(residential_addresh) else residential_addresh
        residential_location = row.get('Residential Address Location', '')
        residential_location = '' if pd.isna(residential_location) else residential_location
        Residential_addresh.objects.update_or_create(
            form_date=formdate,
            defaults={
                'res_address1': row.get('Residential Address Line 1'),
                'res_address2': residential_addresh,
                'res_addresslocation': row.get('Residential Address Location', ''),
                'res_addresspostcode': row.get('Residential Address Postcode', ''),
                'res_addreshstate': row.get('Residential Address State')
            }
        )

        BankDetails.objects.update_or_create(
            form_date=formdate,
            defaults={
                'etaaccountname': row.get('EFT Account Name'),
                'eftbsbnumber': row.get('EFT BSB Number'),
                'eftaccountnumber': row.get('EFT Account Number')
            }
        )

        if pd.notna(row.get('Medicare Type')):
            MedicareInformation.objects.update_or_create(
                form_date=formdate,
                defaults={
                    'medicaretype': row.get('Medicare Type'),
                    'date': row.get('Medicare Date')
                }
            )
            
class UserData(APIView):
    renderer_classes = [UserRenderer]
    
    def get(self, request, format=None):
        users = User.objects.all()  # Ensure correct indentation
        serializer = UserMakaSerializer(users, many=True)  # Specify many=True
        return Response(serializer.data, status=status.HTTP_200_OK)

class DeleteMultipleUsers(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        if request.user.role != 'admin':
            return Response({'detail': 'You do not have permission to perform this action.'}, status=status.HTTP_403_FORBIDDEN)

        user_ids = request.data.get('user')
        if not user_ids: 
            return Response({'error':"User ids must need to provide"})

        if isinstance(user_ids, str):
            try:
                user_ids = json.loads(user_ids)
            except json.JSONDecodeError:
                return Response({'detail': 'User IDs format is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

        # Convert user_ids elements to integers if they are strings
        try:
            user_ids = [int(uid) for uid in user_ids]
        except ValueError:
            return Response({'detail': 'User IDs must be a list of integers.'}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure user_ids is a list of integers
        if not isinstance(user_ids, list) or not all(isinstance(uid, int) for uid in user_ids):
            return Response({'detail': 'User IDs must be a list of integers.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                # Fetch the User instances
                users = User.objects.filter(id__in=user_ids)
                if not users.exists():
                    return Response({'detail': 'No matching users found.'}, status=status.HTTP_404_NOT_FOUND)

                for user in users:
                    if FormDate.objects.filter(user=user).exists():
                        user.delete()
                    else:
                        return Response({'detail': f'Cannot delete user {user.id}. No FormDate data exists for the user.'}, status=status.HTTP_400_BAD_REQUEST)
                
            return Response({'detail': 'Users deleted successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            # print(str(e))
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

