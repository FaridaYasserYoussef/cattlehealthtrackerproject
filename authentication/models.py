from django.db import models
from phonenumber_field.modelfields import PhoneNumberField



# Role choices for users
class UserRoles(models.Model):
    name = models.CharField(max_length=100)

class Features(models.Model):
    name = models.CharField(max_length=100)

class RoleFeature(models.Model):
    feature_id = models.ForeignKey( "Features", on_delete= models.CASCADE)
    role_id = models.ForeignKey( "UserRoles", on_delete= models.CASCADE)
    farm_id = models.ForeignKey( "Farm", on_delete= models.CASCADE)
    
class UserApp(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    mobile_number = PhoneNumberField(unique = True, region = "EG")
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    two_fa_enabled = models.BooleanField(default=False)
    farm = models.ForeignKey('Farm', on_delete=models.SET_NULL, null=True, blank=True)
    role = models.ForeignKey( "UserRoles", on_delete= models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Farm(models.Model):
    name = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)