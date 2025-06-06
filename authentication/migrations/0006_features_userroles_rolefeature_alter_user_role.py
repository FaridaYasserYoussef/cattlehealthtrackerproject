# Generated by Django 5.1.5 on 2025-01-17 20:38

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("authentication", "0005_remove_farm_email_user_farm_user_role"),
    ]

    operations = [
        migrations.CreateModel(
            name="Features",
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
            ],
        ),
        migrations.CreateModel(
            name="UserRoles",
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
            ],
        ),
        migrations.CreateModel(
            name="RoleFeature",
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
                (
                    "farm_id",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="authentication.farm",
                    ),
                ),
                (
                    "feature_id",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="authentication.features",
                    ),
                ),
                (
                    "role_id",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="authentication.userroles",
                    ),
                ),
            ],
        ),
        migrations.AlterField(
            model_name="user",
            name="role",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to="authentication.userroles",
            ),
        ),
    ]
