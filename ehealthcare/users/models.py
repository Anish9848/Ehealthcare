from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings


class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('doctor', 'Doctor'),
        ('patient', 'Patient'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    phone_number = models.CharField(max_length=15, unique=True, null=True, blank=True)  # New field
    

class PatientReport(models.Model):
    REPORT_TYPE_CHOICES = [
        ('video', 'Video Consultation'),
        ('lab', 'Lab Report'),
        ('other', 'Other Report'),
    ]
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to='patient_reports/')
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES, default='other')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
class DoctorReport(models.Model):
    REPORT_TYPE_CHOICES = [
        ('video', 'Video Consultation'),
        ('lab', 'Lab Report'),
        ('other', 'Other Report'),
    ]
    doctor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to='doctor_reports/')
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES, default='other')
    uploaded_at = models.DateTimeField(auto_now_add=True)