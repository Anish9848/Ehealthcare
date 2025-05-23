# Generated by Django 5.1.7 on 2025-04-29 08:48

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0007_appointment"),
    ]

    operations = [
        migrations.CreateModel(
            name="OTPVerification",
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
                ("phone_number", models.CharField(max_length=15)),
                ("otp_hash", models.CharField(max_length=64)),
                ("attempts", models.IntegerField(default=0)),
                ("resend_count", models.IntegerField(default=0)),
                ("first_sent_at", models.DateTimeField(auto_now_add=True)),
                ("last_sent_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField()),
                ("is_verified", models.BooleanField(default=False)),
                ("form_data", models.TextField()),
                ("registration_type", models.CharField(max_length=10)),
            ],
        ),
    ]
