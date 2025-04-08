from django.urls import path
from .views import *

urlpatterns = [
    path("custom_login", login),
    path("otp", verify_otp),
    path("toggle_otp", toggle_2fa),
    path("resend_otp", resend_otp),
    path("change_password", change_password)
]