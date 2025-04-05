from django.shortcuts import render
import json
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
from argon2 import PasswordHasher
from .models import UserApp
from .utils import *
from django.core.mail import send_mail
from django.conf import settings
import time

@csrf_exempt
def login(request):
    if request.method == "POST":
        password = request.POST.get("password")
        email = request.POST.get("email")
        user = UserApp.objects.filter(email = email).first()
        if user:
            password_stored = user.password
            ph = PasswordHasher(hash_len=32, salt_len=16)
            try:
                authenticate_user = ph.verify(password_stored, password)
                if authenticate_user:
                    request.session['email'] = email
                    request.session['user_id'] = user.id
                    request.session['passed_step1'] = True
                    if user.two_fa_enabled:
                        otp = generate_otp()
                        request.session["otp"] = otp
                        request.session['otp_expires'] = time.time() + 300 
                        request.session["otp_count"] = 0 
                        send_mail(
                        'Email Verification OTP',
                        f'Your OTP for email verification is: {otp}',
                        settings.EMAIL_HOST_USER,
                        [email],
                        fail_silently=False,
                        )
                        return JsonResponse({"user_authenticated": True})
                    else:
                        user_details = get_user_details(user.id)
                        return JsonResponse({"detail": "login successful", "user": user_details}, status=200)
            except Exception as e:
                return JsonResponse({"error": "Something went wrong"}, status=500)

        return JsonResponse({"user_authenticated": False})
    

@csrf_exempt
def verify_otp(request):
    if request.method == "POST":
        user_id = request.session.get('user_id')
        otp_expiry = request.session.get("otp_expires")
        user_otp = request.POST.get("otp")
        otp = request.session.get("otp")


        if not otp_expiry or time.time() > otp_expiry:
            new_otp = generate_otp()
            request.session["otp"] = new_otp
            request.session["otp_expires"] = time.time() + 300
            return JsonResponse({"detail": "OTP expired"}, status=403)
        else:
            if user_otp == otp:
                user_details = get_user_details(user_id)
                request.session.pop("otp", None)
                request.session.pop("otp_expires", None)
                request.session.pop("otp_count", None)

                return JsonResponse({"detail": "OTP passed", "user": user_details}, status=200)
            else:
                request.session["otp_count"] = request.session["otp_count"] + 1
                otp_count = request.session["otp_count"]
                if otp_count > 3:
                    request.session.pop("otp", None)
                    request.session.pop("otp_expires", None)
                    request.session.pop("otp_count", None)
                    request.session.pop("user_id", None) 
                    return JsonResponse({"detail": "incorrect otp, surpassed otp trials"})
                return JsonResponse({"detail": "incorrect otp"})
            


@csrf_exempt
def toggle_2fa(request):
    if request.method == "POST":
        email = request.POST.get("email")
        user = UserApp.objects.filter(email = email).first()
        user.two_fa_enabled = False if user.two_fa_enabled == True else True
        user.save()
        return JsonResponse({"detail": "2FA Successfully enabled"})
    return JsonResponse({"detail": "Failed to enable 2FA"})


@csrf_exempt
def resend_otp(request):
    if request.method == "POST":
        email = request.session.get("email")
        otp = generate_otp()
        request.session["otp"] = otp
        request.session['otp_expires'] = time.time() + 300 
        request.session["otp_count"] = 0 
        send_mail(
                    'Email Verification OTP',
                    f'Your OTP for email verification is: {otp}',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                    )
        return JsonResponse({"detail": "OTP resent"})
    return JsonResponse({"detail": "failed to resend OTP"}, status = 500)




@csrf_exempt
def change_password(request):
    if request.method == "POST":
        try:
            new_password = request.POST.get("new_password")
            email = request.POST.get("email")
            user = UserApp.objects.filter(email = email)
            ph = PasswordHasher(hash_len=32, salt_len=16)
            new_hashed_password = ph.hash(password=new_password)
            user.password = new_hashed_password
            user.save()
            return JsonResponse({"detail": "password successfully changed"}, status = 200)
        except:
            return JsonResponse({"detail": "something went wrong while changing the password"}, status = 500)
