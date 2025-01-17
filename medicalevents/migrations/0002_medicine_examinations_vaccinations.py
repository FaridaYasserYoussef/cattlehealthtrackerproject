# Generated by Django 5.1.5 on 2025-01-17 20:38

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cattle", "0001_initial"),
        ("medicalevents", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Medicine",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=100)),
                ("price", models.DecimalField(decimal_places=2, max_digits=10)),
                ("quantity", models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name="Examinations",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("date", models.DateTimeField(auto_now_add=True)),
                ("notes", models.TextField(blank=True, null=True)),
                ("prescription", models.TextField(blank=True, null=True)),
                (
                    "cattle_id",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="cattle.cattle"
                    ),
                ),
                (
                    "diagnosis",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="medicalevents.diseasestypesenglish",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Vaccinations",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("date", models.DateTimeField(auto_now_add=True)),
                ("price", models.DecimalField(decimal_places=2, max_digits=10)),
                ("dose_order", models.PositiveIntegerField(editable=False)),
                (
                    "cattle_id",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="cattle.cattle"
                    ),
                ),
                (
                    "type_id",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="medicalevents.vaccinationtypesenglish",
                    ),
                ),
            ],
        ),
    ]