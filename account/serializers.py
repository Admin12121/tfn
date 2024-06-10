from rest_framework import serializers
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.conf import settings
from .utils import Util
from .models import *
from decouple import config
from django.contrib.auth import get_user_model
from .generate_token import generate_unique_four_digit_number
#User
class FormChargeSerializer(serializers.ModelSerializer):
    class Meta:
        model = FormCharge
        fields = ['amount']

class ReferralUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReferralUser
        fields = '__all__'

class AbnIncomeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Abn_income
        fields = '__all__'

class SpouseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Spouse
        fields = '__all__'

class ResidentialAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Residential_addresh
        fields = '__all__'

class BankDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankDetails
        fields = '__all__'

class MedicareInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = MedicareInformation
        fields = '__all__'

class ApplicableExpensesCategoriesSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApplicableExpensesCategories
        fields = '__all__'

class ApplicableIncomeCategoriesSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApplicableIncomeCategories
        fields = '__all__'

class PassportDrivingLicenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Passport_DrivingLicense
        fields = '__all__'

class SupportingDocumentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SupportingDocuents
        fields = '__all__'

class OccupationDataSerializer(serializers.ModelSerializer):
    applicable_income_categories = ApplicableIncomeCategoriesSerializer(source='applicableincomecategories', read_only=True)
    applicable_expenses_categories = ApplicableExpensesCategoriesSerializer(source='applicableexpensescategories', read_only=True)

    class Meta:
        model = Occupation
        fields = [
            'id', 'occupation',
            'applicable_income_categories',
            'applicable_expenses_categories'
        ]

class OccupationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Occupation
        fields = '__all__'

    def create(self, validated_data):
        occupation = Occupation.objects.create(**validated_data)
        occupation.save()
        return occupation

class AdditionalInformationAndDocumentsSerializer(serializers.ModelSerializer):
    passportdrivinglicense = PassportDrivingLicenseSerializer(many=True, read_only=True)
    supportingdocuments = SupportingDocumentsSerializer(many=True, read_only=True)

    class Meta:
        model = Additionalinformationandsupportingdocuments
        fields = '__all__'

class FormDateSerializer(serializers.ModelSerializer):
    abn_income = AbnIncomeSerializer(read_only=True)
    spouses = SpouseSerializer(read_only=True)
    residential_address = ResidentialAddressSerializer(read_only=True)
    bank_details = BankDetailsSerializer(read_only=True)
    medicare_info = MedicareInformationSerializer(read_only=True)
    occupation = OccupationDataSerializer(read_only=True)
    additional_information = AdditionalInformationAndDocumentsSerializer(read_only=True)

    class Meta:
        model = FormDate
        fields = '__all__'


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'email', 'title', 'first_name', 'middle_name', 'last_name', 'password', 'phone', 'dateofbirth',
            'numberofdependents', 'gender', 'tfn', 'abn', 'spouse', 'medicareinformation','remark',
        ]
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already in use.")
        return value

    def create(self, validated_data):
        referercode = validated_data.pop('referercode', None)
        redeem_code = None

        if referercode:
            try:
                redeem_code = ReferralUser.objects.get(referrercode=referercode)
            except ReferralUser.DoesNotExist:
                raise serializers.ValidationError({"referercode": "Invalid referercode."})

        token = self.context.get('token')
        user = User.objects.create_user(token=token, referercode=redeem_code, **validated_data)
        user.is_active = False
        return user
    
class AdminRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'first_name', 'middle_name', 'last_name', 'role', 'phone', 'password']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is already in use.")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.is_active = True
        user.save()
        return user

class EmailOrUsernameField(serializers.CharField):
    def to_internal_value(self, data):
        if '@' in data:
            return super().to_internal_value(data)
        else:
            user_model = get_user_model()
            try:
                user = user_model.objects.get(tfn=data)
                return user.email
            except user_model.DoesNotExist:
                raise serializers.ValidationError("Enter a valid email address or username.")

class UserLoginSerializer(serializers.ModelSerializer):
    email = EmailOrUsernameField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'token']

class AbnormalLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'password']

class RefUserDataSerializer(serializers.ModelSerializer):
    referral_data = ReferralUserSerializer(source='referuser', read_only=True)
    class Meta:
        model = User
        fields = [
           'id', 'email', 'title', 'first_name', 'middle_name', 'last_name', 'phone', 
            'referral_data', 'is_active', 'role', 'created_at', 'updated_at', 'last_login'
        ]

class AdminandStaffUserDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
           'id', 'email', 'title', 'first_name', 'middle_name', 'last_name', 'phone', 'is_active', 'role', 'created_at', 'updated_at', 'last_login'
        ]

class RefUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'middle_name', 'last_name', 'phone']

class ReferralUserRequiredSerializer(serializers.ModelSerializer):
    user=RefUserSerializer(read_only=True)
    class Meta:
        model = ReferralUser
        fields = ['user']

class RefDataStatusUpdatesSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReferalData
        fields = '__all__'

class RefUserStatusUpdatesSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReferalData
        fields = ['status']

class ReferalDataSerializer(serializers.ModelSerializer):
    user = RefUserSerializer(read_only=True)
    referal = ReferralUserRequiredSerializer(read_only=True)
    class Meta:
        model = ReferalData
        fields = '__all__'

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class ReferalSettlementSerializer(serializers.ModelSerializer):
    refuser_email = serializers.EmailField(source='refuser.user.email', read_only=True)
    refuser_first_name = serializers.CharField(source='refuser.user.first_name', read_only=True)
    refuser_last_name = serializers.CharField(source='refuser.user.last_name', read_only=True)
    users = serializers.SerializerMethodField()

    class Meta:
        model = ReferalSettlement
        fields = ['refuser_email','settledamount','settleddate', 'refuser_first_name', 'refuser_last_name', 'users']

    def get_users(self, obj):
        users_data = []
        for referral_data in obj.user.all():
            user = referral_data.user
            user_data = {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
            users_data.append(user_data)
        return users_data


class UserDataSerializer(serializers.ModelSerializer):
    referral_data = ReferralUserSerializer(source='referercode', read_only=True, many=True)
    refuserstatus = RefUserStatusUpdatesSerializer(source='referral_data', many=True, read_only=True)
    formdata = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'title', 'first_name', 'middle_name', 'last_name', 'phone', 'dateofbirth',
            'numberofdependents', 'gender', 'tfn', 'abn', 'spouse', 'medicareinformation', 'is_export',
            'is_active', 'role', 'status', 'payment_status', 'created_at', 'updated_at', 'last_login',
            'referral_data', 'formdata', 'refuserstatus'
        ]

    def get_formdata(self, obj):
        request = self.context.get('request')
        id_param = request.query_params.get('id')

        user = request.user

        # Check if the user is authenticated and if the requested user is the same as the authenticated user
        if request.user.is_authenticated and obj == user:
            form_dates = obj.formdata.all()
        else:
            if id_param:
                # If the request is for a single user by ID, return all form data
                form_dates = obj.formdata.all()
            else:
                # If the request is for all users, return only current year data
                year_param = request.query_params.get('year', datetime.date.today().year)
                form_dates = obj.formdata.filter(year=year_param)

        form_dates_data = FormDateSerializer(form_dates, many=True).data
        return form_dates_data[0] if form_dates_data and not id_param else form_dates_data


class UserChangePasswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)

  class Meta:
    fields = ['password']

  def validate(self, attrs):
    password = attrs.get('password')
    user = self.context.get('user')
    user.set_password(password)
    user.save()
    return attrs
