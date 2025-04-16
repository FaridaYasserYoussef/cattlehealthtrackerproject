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
        data = json.loads(request.body)
        refresh_token = data.get("refresh")

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
            return Response({"error" : "Invalid refresh token"}, status= status.HTTP_400_BAD_REQUEST)

@csrf_exempt
def logout(request):
    if request.method == "POST":
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                validated_token = AccessToken(token)
                user_id = validated_token['user_id']
                user = UserApp.objects.get(id = user_id)
                if user:
                    data = json.loads(request.body)
                    refresh_token = data["refresh"]
                    old_refresh = RefreshToken(refresh_token)
                    old_refresh.blacklist()
                    return JsonResponse({"detail": "logout Sucessful"}, status = 200)
                print("user was not found")
                return JsonResponse({"error": "user was not found"}, status = 500)
                
            except Exception as e:
                print(str(e))
                return JsonResponse({"error": str(e)}, status = 500)


@csrf_exempt
def login(request):
    if request.method == "POST":
        data = json.loads(request.body)
        password = data.get("password")
        print(password)
        email = data.get("email")
        print(email)
        user = UserApp.objects.filter(email = email).first()
        if user:
            password_stored = user.password
            ph = PasswordHasher(hash_len=32, salt_len=16)
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
                    return JsonResponse({"detail":  "2fa-enabled","user_authenticated": True, "email": email})
                else:
                    user_details = get_user_details(user.id)
                    refresh_token, access_token = get_tokens_for_user(user)
                    return JsonResponse({"detail": "login successful", "user": user_details, "refresh": refresh_token, "access": access_token}, status=200)
            # except Exception as e:
            #     print(str(e))
                # return JsonResponse({"error": "Something went wrong"}, status=500)

        return JsonResponse({"detail":  "login fail","user_authenticated": False}, status = 400)
    

@csrf_exempt
def verify_otp(request):
    if request.method == "POST":
        data = json.loads(request.body)
        user_id = request.session.get('user_id')
        otp_expiry = request.session.get("otp_expires")
        user_otp = data.get("otp")
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
                    return JsonResponse({"detail": "incorrect otp, surpassed otp trials"}, status = 400)
                return JsonResponse({"detail": "incorrect otp"}, status = 400)
            


@csrf_exempt
def toggle_2fa(request):
    if request.method == "POST":
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
                return JsonResponse({"detail": "2FA Successfully toggled", "value" : user.two_fa_enabled}, status = 200)
            except TokenError:
                return JsonResponse({"error": "Invalid or expired token"}, status=401)
            except Exception as e:
                return JsonResponse({"error": "An unexpected error occurred", "message": str(e)}, status=500)
        else:
            return JsonResponse({"error": "Invalid or expired token"}, status=401)
    return JsonResponse({"detail": "post request expected"}, status=405)


@csrf_exempt
def resend_otp(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data["email"]
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
            return JsonResponse({"detail": "OTP resent", "sent": True} ,status = 200)
        except:
            return JsonResponse({"detail": "failed to resend OTP", "sent": False}, status = 500)




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
                    data = json.loads(request.body)
                    new_password = data.get("new_password")
                    old_password = data.get("old_password")
                    ph = PasswordHasher(hash_len=32, salt_len=16)
                    old_hashed_password = ph.hash(password=old_password)
                    if old_hashed_password != user.password:
                        return JsonResponse({"error": "incorrect old password"}, status = 400)
                    new_hashed_password = ph.hash(password=new_password)
                    user.password = new_hashed_password
                    user.save()
                    return JsonResponse({"detail": "password successfully changed"}, status = 200)
                except TokenError:
                    return JsonResponse({"error": "Invalid or expired token"}, status=401)
            else:
                return JsonResponse({"error": "Authorization header missing"}, status=401)
