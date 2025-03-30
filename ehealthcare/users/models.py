from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
import os


class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('doctor', 'Doctor'),
        ('patient', 'Patient'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    phone_number = models.CharField(max_length=15, unique=True, null=True, blank=True)

# Function to generate file path for patient reports
def patient_report_upload_path(instance, filename):
    # Create a folder named after the patient's username
    return os.path.join('patient_reports', instance.patient.username, filename)

# Function to generate file path for doctor reports
def doctor_report_upload_path(instance, filename):
    # Create a folder named after the doctor's username
    return os.path.join('doctor_reports', instance.doctor.username, filename)

class PatientReport(models.Model):
    REPORT_TYPE_CHOICES = [
        ('video', 'Video Consultation'),
        ('lab', 'Lab Report'),
        ('other', 'Other Report'),
    ]
    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to=patient_report_upload_path)  # Use the custom path
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES, default='other')
    uploaded_at = models.DateTimeField(auto_now_add=True)

class DoctorReport(models.Model):
    REPORT_TYPE_CHOICES = [
        ('video', 'Video Consultation'),
        ('lab', 'Lab Report'),
        ('other', 'Other Report'),
    ]
    doctor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to=doctor_report_upload_path)  # Use the custom path
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES, default='other')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
class Appointment(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    patient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="appointments")
    doctor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="appointments_as_doctor")
    date = models.DateField()
    time = models.TimeField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Appointment with Dr. {self.doctor.username} on {self.date} at {self.time}"