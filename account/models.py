from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.db.models.signals import post_save
from django.dispatch import receiver
import threading
import time
from django.template.loader import render_to_string
from django.core.mail import EmailMessage, EmailMultiAlternatives
import pandas as pd
from django.db import transaction, IntegrityError
from django.core.exceptions import ValidationError
from django.core.validators import FileExtensionValidator
from django.core.mail import send_mail, EmailMessage
from django.core.files.base import ContentFile
from PIL import Image
from io import BytesIO
import requests
from cryptography.fernet import Fernet
import qrcode
from tfn import settings
import datetime
from email.mime.image import MIMEImage

def current_year():
    return datetime.date.today().year

def validate_year(value):
    current_year = datetime.date.today().year
    if value < 1900 or value > current_year:
        raise ValidationError(f'{value} is not a valid year. Please enter a year between 1900 and {current_year}.')

class UserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, phone, password=None, **extra_fields):
        if not email:
            raise ValueError('User must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, phone, **extra_fields):
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_admin', True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, first_name, last_name, phone, **extra_fields)

class User(AbstractBaseUser):
    Title = (
        ('Mr', 'Mr'),
        ('Mrs', 'Mrs'),
        ('Ms', 'Ms'),
    )
    Gender = (
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Transgender', 'Transgender'),
        ('non-binary/non-conforming', 'non-binary/non-conforming'),
        ('prefer not to say', 'prefer not to say'),
    )
    ROLE_CHOICES = (
        ('admin', 'admin'),
        ('staff', 'staff'),
        ('referuser', 'referuser'),
        ('user', 'user'),
    )
    Status = (
        ('received', 'received'),
        ('inprogress', 'inprogress'),
        ('pending', 'pending'),
        ('seentforsign', 'seentforsign'),
        ('signed', 'signed'),
        ('lodgedwithato', 'lodgedwithato'),
        ('dormat', 'dormat'),
    )
    Payment_Status = (
        ('paid', 'paid'),
        ('unpaid', 'unpaid'),
    )
    email = models.EmailField(
        verbose_name='Email',
        max_length=255,
        unique=True,
    )
    title = models.CharField(choices=Title, max_length=5, null=True, blank=True)
    first_name = models.CharField(max_length=200)
    middle_name = models.CharField(max_length=200, null=True, blank=True)
    last_name = models.CharField(max_length=200)
    phone = models.CharField(max_length=15)
    dateofbirth = models.CharField(max_length=100,null=True, blank=True)
    numberofdependents = models.IntegerField(null=True, blank=True)
    tfn = models.IntegerField(null=True, blank=True)
    password = models.CharField(max_length=200, null=True, blank=True)
    token = models.CharField(max_length=10, null=True, blank=True, default='1234')
    gender = models.CharField(choices=Gender, max_length=30, null=True, blank=True)
    role = models.CharField(choices=ROLE_CHOICES, max_length=10, default="user")
    abn = models.BooleanField(default=False, null=True, blank=True)
    spouse = models.BooleanField(default=False, null=True, blank=True)
    remark = models.CharField(max_length=100, null=True, blank=True)
    medicareinformation = models.BooleanField(default=False, null=True, blank=True)
    referercode = models.ForeignKey('ReferralUser', on_delete=models.SET_DEFAULT, default=None, null=True, blank=True, related_name='users_with_referercode')
    status = models.CharField(max_length=100,choices=Status, null=True, blank=True, default="received")
    payment_status = models.CharField(max_length=100,choices=Payment_Status , null=True, blank=True, default="unpaid")
    is_export = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(blank=True, null=True)

    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'phone']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin

def remove_token_after_delay(user_id):
    time.sleep(900)  # Wait for 1 minute
    try:
        user = User.objects.get(pk=user_id)
        user.token = None
        user.save()
    except User.DoesNotExist:
        pass 

@receiver(post_save, sender=User)
def schedule_token_removal(sender, instance, created, **kwargs):
    threading.Thread(target=remove_token_after_delay, args=(instance.id,)).start()

class FormDate(models.Model):
    user = models.ForeignKey('User', related_name='formdata', on_delete=models.CASCADE)
    year = models.IntegerField(default=current_year, validators=[validate_year])

    def __str__(self):
        return str(self.year)
    
class FormCharge(models.Model):
    fixed = models.IntegerField(null=True,unique=True,blank=True, default=1)
    amount = models.FloatField(null=True, blank=True)

class ReferralUser(models.Model):
    user = models.OneToOneField('User',related_name='referuser', on_delete=models.CASCADE, null=True, blank=True)
    company = models.CharField(max_length=500, null=True, blank=True)
    company_logo = models.ImageField(upload_to='refuser/logo', null=True, blank=True, validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'pdf'])])
    referrercode = models.CharField(max_length=10, null=True, blank=True)
    isrequired = models.BooleanField(null=True, blank=True)
    commissiontype = models.BooleanField(null=True, blank=True, default=True)
    commission = models.FloatField(null=True, blank=True)
    referrerurl = models.CharField(max_length=500, null=True, blank=True)
    qrcode = models.ImageField(upload_to='refuser/qr', null=True, blank=True, validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'pdf'])])
    
    
    def save(self, *args, **kwargs):
        is_new_instance = not self.pk
        old_instance = None
        if not is_new_instance:
            old_instance = ReferralUser.objects.get(pk=self.pk)
        super().save(*args, **kwargs)

        if self.commission is not None:
            if is_new_instance or (old_instance and old_instance.commission != self.commission):
                self.referrercode = self.generate_referrercode()
                encrypted_data = self.encrypt_data()
                url = self.generate_qr_code(encrypted_data)
                self.referrerurl = url
                super().save(update_fields=['referrercode', 'qrcode', 'referrerurl'])

                self.send_email_with_qrcode()

    def generate_referrercode(self):
        import random
        import string
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

    def encrypt_data(self):
        key = b'HgtCZxpXZNNC3jylJuWypAuT8UnkJxUjrDGhezgdpZI='  # Should be 32 bytes
        f = Fernet(key)
        data = f"{self.referrercode}:{self.user.id}"
        token = f.encrypt(data.encode())
        return token

    def generate_qr_code(self, encrypted_data):
        isreq = self.isrequired
        url = f"https://tax-eight.vercel.app/register/?refer={encrypted_data.decode()}&isrequired={isreq}"
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_H
        )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

        # Fetch and overlay the logo from the provided URL
        logo_url = "https://i.pinimg.com/736x/7d/44/70/7d4470aa3ec5d0eae92709c15cd764ef.jpg"
        response = requests.get(logo_url)
        if response.status_code == 200:
            logo = Image.open(BytesIO(response.content))
            if logo.mode != 'RGBA':
                logo = logo.convert('RGBA')

            # Resize logo
            logo.thumbnail((img.size[0] // 3, img.size[1] // 3), Image.LANCZOS)
            logo_position = (
                (img.size[0] - logo.size[0]) // 2,
                (img.size[1] - logo.size[1]) // 2
            )

            # Create a new image for the combined result
            combined = Image.new('RGBA', img.size)
            combined.paste(img, (0, 0))
            combined.paste(logo, logo_position, logo)

            # Convert back to RGB
            img = combined.convert('RGB')

        # Save the image to an in-memory file
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        file_name = f"{self.referrercode}_qrcode.png"
        self.qrcode.save(file_name, ContentFile(buffer.getvalue()), save=False)
        
        return url

    def send_email_with_qrcode(self):
        if self.qrcode:
            subject = "Your Referral QR Code"
            context = {
                'user': self.user,
                'referrercode': self.referrercode,
                'referrerurl': self.referrerurl,
                'commission': self.commission
            }
            message = render_to_string('qrcode.html', context)
            
            email = EmailMultiAlternatives(
                subject,
                message,
                settings.EMAIL_HOST_USER,
                [self.user.email]
            )
            email.attach_alternative(message, "text/html")
            email.content_subtype = "html"

            # Attach QR code image
            qr_image = self.qrcode.file
            qr_image.open()
            qr_image_content = qr_image.read()
            email.attach(self.qrcode.name, qr_image_content, 'image/png')

            # Embed QR code image in the email
            image = MIMEImage(qr_image_content)
            image.add_header('Content-ID', '<qr_code_image>')
            image.add_header('Content-Disposition', 'inline', filename=self.qrcode.name)
            email.attach(image)

            email.fail_silently = False
            email.send()
            
class Abn_income(models.Model):
    user = models.OneToOneField('User', related_name='abn_income', on_delete=models.CASCADE)
    abn = models.IntegerField()
    natureofworkdone = models.TextField(max_length=2000, null=True, blank=True)
    grossincomereceivedinbank = models.FloatField(null=True, blank=True)

class Spouse(models.Model):
    form_date = models.OneToOneField(FormDate, related_name='spouses', on_delete=models.CASCADE)
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100)
    spouse_taxable_income = models.FloatField(null=True, blank=True)
    dob = models.CharField(max_length=100,null=True,blank=True)

class Residential_addresh(models.Model):
    STATE_CHOICES = (
        ('NSW', 'NSW'),
        ('AAT', 'AAT'),
        ('ACT', 'ACT'),
        ('VIC', 'VIC'),
        ('SA', 'SA'),
        ('QLD', 'QLD'),
        ('NT', 'NT'),
        ('WA', 'WA'),
        ('TAS', 'TAS'),
    )
    form_date = models.OneToOneField(FormDate, related_name='residential_address', on_delete=models.CASCADE)
    res_address1 = models.CharField(max_length=200, null=True, blank=True)
    res_address2 = models.CharField(max_length=200, null=True, blank=True)
    res_addresslocation = models.CharField(max_length=200, null=True, blank=True)
    res_addresspostcode = models.CharField(max_length=100, null=True, blank=True)
    res_addreshstate = models.CharField(choices=STATE_CHOICES, max_length=3)

class BankDetails(models.Model):
    form_date = models.OneToOneField(FormDate, related_name='bank_details', on_delete=models.CASCADE)
    etaaccountname = models.CharField(max_length=200, null=True, blank=True)
    eftbsbnumber = models.CharField(max_length=200, null=True, blank=True)
    eftaccountnumber = models.CharField(max_length=200, null=True, blank=True)

class MedicareInformation(models.Model):
    Medicare_CHOICES = (
        ('partially', 'partially'),
        ('fully', 'fully'),
    )
    form_date = models.OneToOneField(FormDate, related_name='medicare_info', on_delete=models.CASCADE)
    medicaretype = models.CharField(choices=Medicare_CHOICES, max_length=100,null=True, blank=True)
    date = models.CharField(max_length=100,null=True, blank=True)

class Occupation(models.Model):
    form_date = models.OneToOneField(FormDate, related_name='occupation', on_delete=models.CASCADE)
    occupation = models.CharField(max_length=200, null=True, blank=True)

class ApplicableIncomeCategories(models.Model):
    occupation = models.OneToOneField(Occupation, on_delete=models.CASCADE,blank=True,null=True)
    salary_wages = models.BooleanField(default=False)
    salary_wages_amt = models.FloatField(null=True, blank=True)
    pandemic_leave_disaster_payment = models.BooleanField(default=False)
    pandemic_leave_disaster_payment_amt = models.FloatField(null=True, blank=True)
    dividends = models.BooleanField(default=False)
    dividends_amt = models.FloatField(null=True, blank=True)
    employment_share_scheme = models.BooleanField(default=False)
    employment_share_scheme_amt = models.FloatField(null=True, blank=True)
    trust_partnership_distribution = models.BooleanField(default=False)
    trust_partnership_distribution_amt = models.FloatField(null=True, blank=True)
    income_from_business = models.BooleanField(default=False)
    income_from_business_amt = models.FloatField(null=True, blank=True)
    capital_gain_loss = models.BooleanField(default=False)
    capital_gain_loss_amt = models.FloatField(null=True, blank=True)
    rental_income = models.BooleanField(default=False)
    rental_income_amt = models.FloatField(null=True, blank=True)
    foreign_income = models.BooleanField(default=False)
    foreign_income_amt = models.FloatField(null=True, blank=True)
    investment_in_share_crypto_cfd_forex_trading = models.BooleanField(default=False)
    investment_in_share_crypto_cfd_forex_trading_amt = models.FloatField(null=True, blank=True)
    other_income_not_specified_above = models.BooleanField(default=False)
    other_income_not_specified_above_amt = models.FloatField(null=True, blank=True)

class ApplicableExpensesCategories(models.Model):
    occupation = models.OneToOneField(Occupation, on_delete=models.CASCADE,blank=True, null=True)
    work_related_car_expenses = models.BooleanField(default=False)
    work_related_car_expenses_amt = models.FloatField(null=True, blank=True)
    work_related_travel_expenses = models.BooleanField(default=False)
    work_related_travel_expenses_amt = models.FloatField(null=True, blank=True)
    work_related_clothing_laundry_dry_cleaning = models.BooleanField(default=False)
    work_related_clothing_laundry_dry_cleaning_amt = models.FloatField(null=True, blank=True)
    work_related_self_education_expenses = models.BooleanField(default=False)
    work_related_self_education_expenses_amt = models.FloatField(null=True, blank=True)
    gift_donation = models.BooleanField(default=False)
    gift_donation_amt = models.FloatField(null=True, blank=True)
    tax_agents_fee = models.BooleanField(default=False)
    tax_agents_fee_amt = models.FloatField(null=True, blank=True)
    income_protection_insurance = models.BooleanField(default=False)
    income_protection_insurance_amt = models.FloatField(null=True, blank=True)
    personal_contribution_to_super = models.BooleanField(default=False)
    personal_contribution_to_super_amt = models.FloatField(null=True, blank=True)
    professional_membership_union_fee = models.BooleanField(default=False)
    professional_membership_union_fee_amt = models.FloatField(null=True, blank=True)
    other_expenses_not_specified_above = models.BooleanField(default=False)
    other_expenses_not_specified_above_amt = models.FloatField(null=True, blank=True)

class Additionalinformationandsupportingdocuments(models.Model):
    form_date = models.OneToOneField(FormDate, related_name='additional_information', on_delete=models.CASCADE)
    note = models.TextField(max_length=2000, null=True, blank=True)

class Passport_DrivingLicense(models.Model):
    AddFile = models.ForeignKey(Additionalinformationandsupportingdocuments, on_delete=models.CASCADE, related_name='passportdrivinglicense', null=True, blank=True)
    passport = models.ImageField(upload_to='user/documents', null=True, blank=True,validators=[ FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'pdf'])] ) 

class SupportingDocuents(models.Model):
    AddFile = models.ForeignKey(Additionalinformationandsupportingdocuments, on_delete=models.CASCADE, related_name='supportingdocuments', null=True, blank=True)
    supportingdocuments = models.ImageField(upload_to='user/documents', null=True, blank=True,validators=[ FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'pdf'])] ) 

class ReferalData(models.Model):
    Medicare_CHOICES = (
        ('not due', 'not due'),
        ('payable', 'payable'),
        ('settled', 'settled'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='referral_data')
    referal = models.ForeignKey(ReferralUser, on_delete=models.SET_DEFAULT,default=None, null=True, blank=True)
    status = models.CharField(choices=Medicare_CHOICES, max_length=100,null=True, blank=True, default='not due')
    settleddate = models.CharField(max_length=100,null=True, blank=True)    
    commissionamt = models.FloatField(null=True, blank=True)

class ReferalSettlement(models.Model):
    refuser = models.ForeignKey(ReferralUser, on_delete=models.CASCADE, null=True, blank=True, related_name='referral_user_settlement')  
    user = models.ManyToManyField(ReferalData, blank=True, related_name='user_data')
    settledamount = models.FloatField(null=True, blank=True)
    settleddate = models.CharField(max_length=100,null=True, blank=True)    

class ImportedFile(models.Model):
    file_name = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=255, unique=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)