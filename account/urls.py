from django.urls import path
from .views import *
from rest_framework_simplejwt.views import(
    TokenRefreshView,
)

urlpatterns = [

    path('validator/', EmailValidatorView.as_view(), name='validator'),
    path('add-document/', AddDocumentView.as_view(), name='add-document'),
    path('checkuser/', CheckEmailView.as_view(), name='checkuser'),
    path('admin_register/', AdminRegistrationView.as_view(), name='admin_register'),
    path('user_register/', UserRegistrationView.as_view(), name='user_register'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('clientsupdates/', ClientuserStatusUpdates.as_view(), name='clientsupdates'),
    path('activate/', UserActivationView.as_view() , name='activate'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('abnormallogin/', AbNormalUser.as_view(), name='abnormallogin'),
    path('referaluserdata/', RefUserData.as_view(), name='referaluserdata'),
    path('firstatusupdates/', RefDataStatusUpdates.as_view(), name='firstatusupdates'),
    path('settledstatement/', ReferalSettlementListView.as_view(), name='settledstatement'),
    path('alluser/', AllUsersView.as_view(), name='alluser'),
    path('formdata/', FormChargeView.as_view(), name='formdata'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('exportdata/', DataExported.as_view(), name='exportdata'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('import-excel/', ImportUserDataView.as_view(), name='import-excel'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
    path('send-reset-password-email/', SendUserPasswordResetEmailView.as_view(), name='send-reset-password-email'),
]