# Generated by Django 5.1.5 on 2025-01-16 18:46

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0004_farm"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="farm",
            name="email",
        ),
        migrations.AddField(
            model_name="user",
            name="farm",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to="authentication.farm",
            ),
        ),
        migrations.AddField(
            model_name="user",
            name="role",
            field=models.CharField(
                choices=[
                    ("admin", "Admin"),
                    ("vet", "Vet"),
                    ("accountant", "Accountant"),
                ],
                default="accountant",
                max_length=20,
            ),
        ),
    ]
