from django.db import models


# Role choices for users
class UserRoles(models.Model):
    name = models.CharField(max_length=100)

class Features(models.Model):
    name = models.CharField(max_length=100)

class RoleFeature(models.Model):
    feature_id = models.ForeignKey( "Features", on_delete= models.CASCADE)
    role_id = models.ForeignKey( "UserRoles", on_delete= models.CASCADE)
    farm_id = models.ForeignKey( "Farm", on_delete= models.CASCADE)
class User(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    farm = models.ForeignKey('Farm', on_delete=models.SET_NULL, null=True, blank=True)
    role = models.ForeignKey( "UserRoles", on_delete= models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Farm(models.Model):
    name = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"
