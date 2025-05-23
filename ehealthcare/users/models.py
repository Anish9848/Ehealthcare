from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
import os
from django.utils import timezone
import random
import hashlib

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('doctor', 'Doctor'),
        ('patient', 'Patient'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)
    phone_number = models.CharField(max_length=15, null=True, blank=True)  
    consultation_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    is_verified = models.BooleanField(default=False)  
    
    
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
    doctor = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='doctor_appointments')
    patient = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='patient_appointments')
    date = models.DateField()
    time = models.CharField(max_length=10)  # Store time as "HH:MM" format
    status = models.CharField(max_length=20, default='pending')  # pending, approved, conducted, cancelled
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Add these new fields:
    title = models.CharField(max_length=100, blank=True, null=True)
    is_recurring = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-date', '-time']

class OTPVerification(models.Model):
    phone_number = models.CharField(max_length=15)
    otp_hash = models.CharField(max_length=64)  # Store hashed OTP
    attempts = models.IntegerField(default=0)
    resend_count = models.IntegerField(default=0)
    first_sent_at = models.DateTimeField(auto_now_add=True)
    last_sent_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)
    
    # Store form data as JSON
    form_data = models.TextField()
    registration_type = models.CharField(max_length=10)  # 'patient', 'doctor', 'admin'
    
    def __str__(self):
        return f"OTP for {self.phone_number}"

    def is_expired(self):
        return timezone.now() > self.expires_at
    
    @classmethod
    def generate_otp(cls):
        """Generate 6-digit OTP"""
        return str(random.randint(100000, 999999))
    
    @classmethod
    def hash_otp(cls, otp, phone_number):
        """Hash OTP with phone number as salt"""
        key = f"{otp}:{phone_number}"
        return hashlib.sha256(key.encode()).hexdigest()
    
    def verify_otp(self, entered_otp):
        """Verify OTP and update attempts"""
        self.attempts += 1
        self.save()
        
        if self.is_expired():
            return False, "OTP expired"
        
        if self.attempts > 5:
            return False, "Too many attempts"
        
        hashed_input = self.hash_otp(entered_otp, self.phone_number)
        if hashed_input == self.otp_hash:
            self.is_verified = True
            self.save()
            return True, "OTP verified"
        
        return False, "Invalid OTP"

# Add this after your other model definitions
class DoctorAvailability(models.Model):
    DAY_CHOICES = [
        (0, 'Sunday'),
        (1, 'Monday'),
        (2, 'Tuesday'),
        (3, 'Wednesday'),
        (4, 'Thursday'),
        (5, 'Friday'),
        # Saturday is excluded as it's a non-working day
    ]
    
    doctor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="availabilities")
    day_of_week = models.IntegerField(choices=DAY_CHOICES)
    start_time = models.TimeField()
    end_time = models.TimeField()
    
    class Meta:
        unique_together = ['doctor', 'day_of_week', 'start_time']
        ordering = ['day_of_week', 'start_time']
    
    def __str__(self):
        return f"{self.get_day_of_week_display()}: {self.start_time.strftime('%H:%M')} - {self.end_time.strftime('%H:%M')}"