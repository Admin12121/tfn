from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import *

class FormDateInline(admin.TabularInline):
    model = FormDate
    extra = 1  # Number of empty forms to display

class ReferralUserInline(admin.TabularInline):
    model = ReferralUser
    extra = 1  # Number of empty forms to display

class AbnIncomeInline(admin.TabularInline):
    model = Abn_income
    extra = 1

class SpouseInline(admin.TabularInline):
    model = Spouse
    extra = 1

class ResidentialAddressInline(admin.TabularInline):
    model = Residential_addresh
    extra = 1

class BankDetailsInline(admin.TabularInline):
    model = BankDetails
    extra = 1

class MedicareInformationInline(admin.TabularInline):
    model = MedicareInformation
    extra = 1

class ApplicableIncomeCategoriesInline(admin.TabularInline):
    model = ApplicableIncomeCategories
    extra = 1

class ApplicableExpensesCategoriesInline(admin.TabularInline):
    model = ApplicableExpensesCategories
    extra = 1

class OccupationAdmin(admin.ModelAdmin):
    inlines = [ApplicableIncomeCategoriesInline, ApplicableExpensesCategoriesInline]

class OccupationInline(admin.TabularInline):
    model = Occupation
    extra = 1

class PassportDrivingLicenseInline(admin.TabularInline):
    model = Passport_DrivingLicense
    extra = 1

class SupportingDocumentsInline(admin.TabularInline):
    model = SupportingDocuents
    extra = 1

class AdditionalInformationAndSupportingDocumentsAdmin(admin.ModelAdmin):
    inlines = [PassportDrivingLicenseInline, SupportingDocumentsInline]

class AdditionalInformationAndSupportingDocumentsInline(admin.TabularInline):
    model = Additionalinformationandsupportingdocuments
    extra = 1

class FormDateAdmin(admin.ModelAdmin):
    inlines = [
        AbnIncomeInline,
        SpouseInline,
        ResidentialAddressInline,
        BankDetailsInline,
        MedicareInformationInline,
        OccupationInline,
        AdditionalInformationAndSupportingDocumentsInline,
    ]
    list_display = ('user', 'year')
    list_filter = ('year',)
    search_fields = ('user__email', 'year')
    ordering = ('user', 'year')

class UserModelAdmin(BaseUserAdmin):
    list_display = ('email', 'first_name', 'role', 'phone', 'gender')
    list_filter = ('is_admin',)
    fieldsets = (
        ('User Credentials', {'fields': ('email', 'tfn', 'token', 'password')}),
        ('Personal info', {'fields': ('first_name', 'middle_name', 'last_name', 'phone', 'dateofbirth', 'numberofdependents', 'gender', 'abn', 'spouse','remark', 'referercode', 'created_at', 'last_login')}),
        ('Permissions', {'fields': ('is_export', 'payment_status', 'role', 'is_active', 'is_admin',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'token'),
        }),
    )
    readonly_fields = ('created_at', 'tfn')
    search_fields = ('tfn', 'email', 'first_name')
    ordering = ('email', 'id')
    filter_horizontal = ()
    inlines = [
        FormDateInline,
        ReferralUserInline,
    ]

class ReferralUserAdmin(admin.ModelAdmin):
    list_display = ('user', 'company', 'referrercode', 'commissiontype', 'commission')

    def get_readonly_fields(self, request, obj=None):
        if obj:  # obj is not None if this is a change page.
            return ['referrercode']  # Make referrercode read-only after creation
        else:
            return []

# admin.site.register(FormDate, FormDateAdmin)
# admin.site.register(ReferralUser, ReferralUserAdmin)
admin.site.register(User, UserModelAdmin)
admin.site.register(Occupation, OccupationAdmin)
# admin.site.register(Additionalinformationandsupportingdocuments, AdditionalInformationAndSupportingDocumentsAdmin)

# admin.site.register(User)
admin.site.register(ReferalData)
admin.site.register(Passport_DrivingLicense)
admin.site.register(ReferalSettlement)
admin.site.register(FormCharge)
admin.site.register(FormDate)
admin.site.register(Abn_income)
admin.site.register(Spouse)
admin.site.register(Residential_addresh)
admin.site.register(BankDetails)
admin.site.register(MedicareInformation)
