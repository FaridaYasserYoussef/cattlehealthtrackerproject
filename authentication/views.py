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
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from datetime import timedelta
from django.conf import settings
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken


CUSTOM_REFRESH_LIFETIME = timedelta(days = 30)
class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get("refresh")

        if not refresh_token:
            return Response({"error":"Refresh token missing"}, status= status.HTTP_400_BAD_REQUEST)
        
        try:
            old_refresh = RefreshToken(refresh_token)
            user = old_refresh.user
            old_refresh.blacklist()
            new_refresh = RefreshToken.for_user(user)
            new_refresh.set_exp(from_time= None, lifetime= CUSTOM_REFRESH_LIFETIME)

            return Response({
                "refresh": str(new_refresh),
                "access": str(new_refresh.access_token)
            })
        
        except Exception as e:
            return Response({"error" : "Invalid refresh token"}, status= status.HTTP_401_UNAUTHORIZED)


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
                        refresh_token, access_token = get_tokens_for_user(user)
                        return JsonResponse({"detail": "login successful", "user": user_details, "refresh": refresh_token, "access": access_token}, status=200)
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
                user = UserApp.objects.get(id = user_id)
                refresh_token, access_token = get_tokens_for_user(user)
                return JsonResponse({"detail": "OTP passed", "user": user_details, "refresh": refresh_token, "access": access_token}, status=200)
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
        # email = request.POST.get("email")
        # user = UserApp.objects.filter(email = email).first()
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                validated_token = AccessToken(token)
                user_id = validated_token['user_id']
                user = UserApp.objects.get(id = user_id)
                user.two_fa_enabled = False if user.two_fa_enabled == True else True
                user.save()
                return JsonResponse({"detail": "2FA Successfully enabled"})
            except TokenError:
                return JsonResponse({"error": "Invalid or expired token"}, status=401)
        else:
            return JsonResponse({"error": "Invalid or expired token"}, status=401)
    return JsonResponse({"detail": "Failed to enable 2FA"})


@csrf_exempt
def resend_otp(request):
    if request.method == "POST":
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                validated_token = AccessToken(token)
                user_id = validated_token['user_id']
                user = UserApp.objects.get(id = user_id)
                email = user.email
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
            except TokenError:
                return JsonResponse({"error": "Invalid or expired token"}, status=401)
    return JsonResponse({"detail": "failed to resend OTP"}, status = 500)




@csrf_exempt
def change_password(request):
    if request.method == "POST":
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                try:
                    validated_token = AccessToken(token)
                    user_id  = validated_token["user_id"]
                    user = UserApp.objects.get(id = user_id)
                    new_password = request.POST.get("new_password")
                    old_password = request.POST.get("old_password")
                    ph = PasswordHasher(hash_len=32, salt_len=16)
                    old_hashed_password = ph.hash(password=old_password)
                    if old_hashed_password != user.password:
                        return JsonResponse({"detail": "incorrect old password"}, status = 400)
                    new_hashed_password = ph.hash(password=new_password)
                    user.password = new_hashed_password
                    user.save()
                    return JsonResponse({"detail": "password successfully changed"}, status = 200)
                except TokenError:
                    return JsonResponse({"error": "Invalid or expired token"}, status=401)
            else:
                return JsonResponse({"error": "Authorization header missing"}, status=401)
