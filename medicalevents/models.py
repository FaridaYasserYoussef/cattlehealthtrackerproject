from django.db import models

# Create your models here.
class VaccinationTypesArabic(models.Model):
    name = models.CharField(max_length=100)


class VaccinationTypesEnglish(models.Model):
    name = models.CharField(max_length=100)

class DiseasesTypesArabic(models.Model):
    name = models.CharField(max_length=100)


class DiseasesTypesEnglish(models.Model):
    name = models.CharField(max_length=100)


class Vaccinations(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    type_id = models.ForeignKey(VaccinationTypesEnglish, on_delete=models.SET_NULL, null = True)
    cattle_id = models.ForeignKey("cattle.Cattle", on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    dose_order= models.PositiveIntegerField(editable=False)

    def save(self, *args, **kwargs):
        # Calculate the dose order
        existing_records = Vaccinations.objects.filter(
            type_id=self.type_id,
            cattle_id=self.cattle_id
        ).count()
        self.dose_order = existing_records + 1  # Next dose order
        super().save(*args, **kwargs)

class Examinations(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    diagnosis = models.ForeignKey(DiseasesTypesEnglish, on_delete=models.SET_NULL, null =  True)
    cattle_id = models.ForeignKey("cattle.Cattle", on_delete=models.CASCADE)
    notes = models.TextField(null=True, blank=True)  # Free text field for notes
    prescription = models.TextField(null=True, blank=True)

class Medicine(models.Model):
    name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity  = models.IntegerField() 