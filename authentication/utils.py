import pyotp
from datetime import datetime, timedelta
from .models import UserApp, RoleFeature
def generate_otp():
    totp = pyotp.TOTP(pyotp.random_base32())  # 5 minutes validity
    return totp.now()

def verify_otp(otp, user_otp):
    return otp == user_otp

def get_user_details(user_id):
    user = UserApp.objects.filter(id = user_id).first()
    final_result = {"first_name": user.first_name, 
                    "last_name": user.last_name, 
                    "mobile_number": user.mobile_number, 
                    "email" : user.email,
                    "two_fa_enabled": user.two_fa_enabled,
                    "role": user.role.name
                    }
    
    accesible_features = RoleFeature.objects.filter(role = user.role)
    feature_names = [role_feature.feature_id.name for role_feature in accesible_features]
    final_result["features"] = feature_names
    return final_result

    