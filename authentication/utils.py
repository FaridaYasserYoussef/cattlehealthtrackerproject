import pyotp
from datetime import datetime, timedelta
from .models import UserApp, RoleFeature
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
import boto3
def generate_otp():
    totp = pyotp.TOTP(pyotp.random_base32())  # 5 minutes validity
    return totp.now()

def verify_otp(otp, user_otp):
    return otp == user_otp

def get_user_details(user_id):
    user = UserApp.objects.filter(id = user_id).first()
    final_result = {"first_name": user.first_name, 
                    "last_name": user.last_name, 
                    "mobile_number": str(user.mobile_number), 
                    "email" : user.email,
                    "two_fa_enabled": user.two_fa_enabled,
                    "role": user.role.name
                    }
    
    accesible_features = RoleFeature.objects.filter(role_id = user.role_id)
    feature_names = [role_feature.feature_id.name for role_feature in accesible_features]
    final_result["features"] = feature_names
    return final_result


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh_token = str(refresh)
    # print(type(refresh_token))
    access_token = str(refresh.access_token)
    # print(type(access_token))
    return refresh_token, access_token


class EmailContent:
    emailAddress
    message
    subject

    def __init__(self, emailAddress, message, subject):
        self.emailAddress = emailAddress
        self.message = message
        self.subject = subject


def get_ses_client():
    return boto3.client(
        'ses',
        aws_access_key_id = settings.AWS_ACCESS_KEY,
        aws_secret_access_key = settings.AWS_SECRET_KEY,
        region_name = settings.AWS_REGION
    )

def send_email(emailContent: EmailContent):
    try:
        ses = get_ses_client()
        response = ses.send_email(
            Source = settings.EMAIL_HOST_USER,
            Destination={'ToAddresses': emailContent.emailAddress},
            Message={
            'Subject': {'Data': emailContent.subject},
            'Body': {'Text': {'Data': emailContent.message}},
        }
        )
        return {"Message": "email sent"}

    except Exception as e:
        raise Exception(str(e))