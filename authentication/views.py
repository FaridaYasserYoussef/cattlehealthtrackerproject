from django.shortcuts import render
import json
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
from argon2 import PasswordHasher
from .models import UserApp
from .utils import *
from django.conf import settings
import traceback
import time
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from datetime import timedelta
from django.conf import settings
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
import traceback
import argon2
from django.core.cache import cache
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


CUSTOM_REFRESH_LIFETIME = timedelta(days = 30)
class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        refresh_token = data.get("refresh")

        if not refresh_token:
            print("Refresh token missing")
            return Response({"error":"Refresh token missing"}, status= status.HTTP_400_BAD_REQUEST)
        
        try:
            old_refresh = RefreshToken(refresh_token)
            user_id = old_refresh.get("user_id")
            user = UserApp.objects.get(id=user_id)
            old_refresh.blacklist()
            new_refresh = RefreshToken.for_user(user)
            new_refresh.set_exp(from_time= None, lifetime= CUSTOM_REFRESH_LIFETIME)

            return Response({
                "refresh": str(new_refresh),
                "access": str(new_refresh.access_token)
            })
        except TokenError as e:
            
            return Response({"error" : "Refresh token expired"}, status= status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            traceb = traceback.format_exc()
            print(traceb)
            return Response({"error" : str(e)}, status= status.HTTP_400_BAD_REQUEST)

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
            except TokenError:
                return JsonResponse({"error": "Invalid or expired access token"}, status=401)
            except Exception as e:
                print(str(e))
                return JsonResponse({"error": str(e)}, status = 500)


@csrf_exempt
def login(request):
    if request.method == "POST":
        data = json.loads(request.body)
        password = data.get("password")
        # print(password)
        email = data.get("email")
        # print(email)
        user = UserApp.objects.filter(email = email).first()
        if user:
            # print("user found")
            password_stored = user.password
            ph = PasswordHasher(hash_len=32, salt_len=16)
            try:
                authenticate_user = ph.verify(password_stored, password)
                # print(authenticate_user)
                if authenticate_user:


                    if user.two_fa_enabled:
                        otp = generate_otp()
                        cache.set(f"otp:{email}", otp, timeout=300)
                        # request.session["otp"] = otp
                        try:
                            send_email(EmailContent(email, f'Your OTP is: {otp}', "OTP"))
                            cache.set(f"otp_expires:{email}", time.time() + 300, timeout=300)
                            cache.set(f"otp_attempts:{email}", 0, timeout=300) 
                            # request.session["otp_count"] = 0 
                            # request.session["otp_resend_cool_down"] = time.time() + 300
                            cache.set(f"otp_resend_cool_down:{email}", time.time() + 10) 
                            return JsonResponse({"detail":  "2fa-enabled","user_authenticated": True, "email": email, "resend_cooldown":cache.get(f"otp_resend_cool_down:{email}")})
                        except Exception as e:
                            return JsonResponse({"error": "Failed to send OTP email", "message": str(e)}, status=500)
                    else:
                        try:
                            user_details = get_user_details(user.id)
                            # print(user_details)
                            refresh_token, access_token = get_tokens_for_user(user)
                            return JsonResponse({"detail": "login successful", "user": user_details, "refresh": refresh_token, "access": access_token}, status=200)
                        except e:
                            print(str(e))
            except argon2.exceptions.VerifyMismatchError:
                # print("user_authenticated")
                return JsonResponse({"error":  "login fail","user_authenticated": False}, status = 400)

            # except Exception as e:
            #     print(str(e))
                # return JsonResponse({"error": "Something went wrong"}, status=500)

        return JsonResponse({"detail":  "login fail","user_authenticated": False}, status = 400)
    

@csrf_exempt
def verify_otp(request):
    if request.method == "POST":
        data = json.loads(request.body)
        # user_id = request.session.get('user_id')
        # otp_expiry = request.session.get("otp_expires")
        email = data.get("email")
        otp_expiry = cache.get(f"otp_expires:{email}")
        user_otp = data.get("otp")
        # otp = request.session.get("otp")
        otp = cache.get(f"otp:{email}")
        # otp_verify_cooldown = request.session.get("otp_verify_cooldown")
        otp_verify_cooldown = cache.get(f"otp_verify_cooldown:{email}")

  
        if not otp_expiry:
            print("OTP not set ask for an otp resend")
            return JsonResponse({"detail": "OTP not set ask for an otp resend"}, status=403)
        if time.time() > otp_expiry:

            print("OTP expired ask for an otp resend")
            return JsonResponse({"detail": "OTP expired ask for an otp resend"}, status=403)
        if otp_verify_cooldown and time.time() < otp_verify_cooldown:
            print("OTP cool down did not end")
            return JsonResponse({"detail": "OTP cool down did not end"}, status=429)
        else:
            if user_otp == otp:
                user = UserApp.objects.filter(email = email).first()
                user_id = user.pk
                user_details = get_user_details(user_id)
                # request.session.pop("otp", None)
                cache.delete(f"otp:{email}")
                # request.session.pop("otp_expires", None)
                cache.delete(f"otp_expires:{email}")
                # request.session.pop("otp_count", None)
                cache.delete(f"otp_attempts:{email}")
                cache.delete(f"otp_resend_cool_down:{email}")
                cache.delete(f"otp_verify_cooldown:{email}")
                refresh_token, access_token = get_tokens_for_user(user)
                print("OTP passed")
                return JsonResponse({"detail": "OTP passed", "user": user_details, "refresh": refresh_token, "access": access_token}, status=200)
            else:
                # request.session["otp_count"] = request.session["otp_count"] + 1
                # otp_count = request.session["otp_count"]
                attempts = cache.get(f"otp_attempts:{email}", 0)
                if attempts > 3:
                    # request.session.pop("otp", None)
                    cache.delete(f"otp:{email}")
                    # request.session.pop("otp_expires", None)
                    cache.delete(f"otp_expires:{email}")
                    # request.session.pop("otp_count", None)
                    cache.delete(f"otp_attempts:{email}")
                    # request.session.pop("user_id", None)
                    # request.session.pop("otp_verify_cooldown", None)
                    cache.delete(f"otp_verify_cooldown:{email}")
                    cache.delete(f"otp_resend_cool_down:{email}")
                    print("incorrect otp, surpassed otp trials")
                    return JsonResponse({"detail": "incorrect otp, surpassed otp trials"}, status = 400)
                cache.set(f"otp_attempts:{email}", attempts + 1, timeout= 300)
                # request.session["otp_verify_cooldown"] = time.time() + 10
                cache.set(f"otp_verify_cooldown:{email}", time.time() +10)
                print("incorrect otp")
                return JsonResponse({"detail": "incorrect otp", "otp_verify_cooldown": cache.get(f"otp_verify_cooldown:{email}")}, status = 400)
            


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
                return JsonResponse({"error": "Invalid or expired access token"}, status=401)
            except Exception as e:
                return JsonResponse({"error": "An unexpected error occurred", "message": str(e)}, status=500)
        else:
            return JsonResponse({"error": "Authorization header missing"}, status=401)
    return JsonResponse({"detail": "post request expected"}, status=405)


@csrf_exempt
def resend_otp(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data["email"]
            otp = generate_otp()
            # request.session["otp"] = otp
            cache.set(f"otp:{email}", otp, timeout= 300)
            # request.session['otp_expires'] = time.time() + 300 
            cache.set(f"otp_expires:{email}", time.time() + 300, timeout= 300)
            # request.session["otp_count"] = 0
            cache.set(f"otp_attempts:{email}", 0, timeout=300)
            cool_down = cache.get(f"otp_resend_cool_down:{email}")
            print("cooldown is ", cool_down)
            if time.time() > cool_down:
                try:
                    send_email(EmailContent(email, f'Your OTP is: {otp}', "OTP"))
                    cache.set(f"otp_resend_cool_down:{email}", time.time() + 10)
                    return JsonResponse({"detail": "OTP resent", "sent": True, "otp_resend_cool_down": cache.get(f"otp_resend_cool_down:{email}")} ,status = 200)
                except Exception as e:
                    print("Error in sending OTP email:", str(e))
                    traceback.print_exc()  # Full traceback in logs
                    return JsonResponse({"error": "Failed to send OTP email", "message": str(e)}, status=500)
            else:
                return JsonResponse({"detail": "resend otp cool down did not pass", "sent": False} ,status = 429)
        except:
            print("Error in resend_otp:", str(e))
            traceback.print_exc()  # Full traceback in logs
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
                    # old_hashed_password = ph.hash(password=old_password)
                    try:
                        ph.verify(user.password, old_password)
                    except:
                        return JsonResponse({"error": "incorrect old password"}, status = 400)
                    new_hashed_password = ph.hash(password=new_password)
                    user.password = new_hashed_password
                    user.save()
                    return JsonResponse({"detail": "password successfully changed"}, status = 200)
                except TokenError:
                    return JsonResponse({"error": "Invalid or expired access token"}, status=401)
            else:
                return JsonResponse({"error": "Authorization header missing"}, status=401)


@csrf_exempt
def send_password_reset_email(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email =  data.get("email")
        user = UserApp.objects.filter(email = email).first()
        if user:
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = f"https://resetpasswordfarmbuild.vercel.app?uid={uid}&token={token}"
            try:
                send_email(EmailContent(email, f'Reset link: {reset_link}', "Password Reset"))
                return JsonResponse({"detail": "reset link sent successfully"}, status = 200)
            except Exception as e:
                print("failed to send email")
                return JsonResponse({"error": "failed to send email"}, status = 400)
        else:
            return JsonResponse({"error": "user not found"}, status = 400)
        # cache.set(f"otp:{email}", otp, timeout= 300)




@csrf_exempt
def reset_password_from_link(request):
    if request.method == "POST":
        data = json.loads(request.body)
        uidb64 = data.get('uid')
        token = data.get('token')
        new_password = data.get('new_password')
        try:
            uid = urlsafe_base64_encode(uidb64).decode()
            user = UserApp.objects.get(id = uid)
            if not user:
                return JsonResponse({"error": "user not found"}, status = 400)
        except (TypeError, ValueError, OverflowError):
            return JsonResponse({'error': 'Invalid token'}, status=400)
        
        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return JsonResponse({"detail": "Password reset successful"}, status = 200)
        else:
            return JsonResponse({"error": "Invalid or expired token"}, status = 400)
