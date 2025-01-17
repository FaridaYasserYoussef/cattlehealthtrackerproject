from django.db import models

# Create your models here.
GENDER_CHOICES = [
    ('M', 'Male'),
    ('F', 'Female'),
]

VACCINATION_STATUS_CHOICES = [
    ('UP', 'Up to Date'),
    ('NU', 'Not Up to Date'),
]
class Cattle(models.Model):
    tag_number = models.IntegerField()
    gender = models.CharField(
         max_length=1,  # Limit to one character
        choices=GENDER_CHOICES,  # Add the predef
    )
    birth_date = models.DateField()
    weight = models.DecimalField(max_digits=10, decimal_places=2)

class CattleMedicalInfo(models.Model):
    last_vaccination_date = models.DateField(null = True)
    cattle_id = models.ForeignKey(Cattle, on_delete=models.CASCADE)
    vaccination_status = models.CharField(
        null= True,
         max_length=2,  # Limit to 2 characters ('UP' or 'NU')
        choices=VACCINATION_STATUS_CHOICES,
    )
    due_vaccine = models.ForeignKey("medicalevents.VaccinationTypesEnglish", null = True, on_delete= models.SET_NULL)

