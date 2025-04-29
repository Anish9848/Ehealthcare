from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import CustomUser, PatientReport, DoctorReport, Appointment, DoctorAvailability
from django.core.files.storage import FileSystemStorage
from .forms import PatientReportForm
from django.http import JsonResponse

# Login view
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Redirect based on user role
            if user.role == "admin":
                return redirect("admin_home")
            elif user.role == "doctor":
                return redirect("doctor_home")
            elif user.role == "patient":
                return redirect("patient_home")
        else:
            messages.error(request, "Invalid username or password")
    return render(request, "users/login.html")


# Logout view
def logout_view(request):
    logout(request)
    return redirect("login")  # Redirect to the login page after logout


# Doctor home view
from django.db.models.functions import TruncMonth
from django.db.models import Count
from datetime import datetime

@login_required
def doctor_home_view(request):
    if request.user.role != "doctor":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")

    # Fetch appointment data
    conducted_meetings = Appointment.objects.filter(doctor=request.user, status="conducted").count()
    scheduled_meetings = Appointment.objects.filter(doctor=request.user, status="approved").count()
    pending_meetings = Appointment.objects.filter(doctor=request.user, status="pending").count()

    # Monthly data for line graph
    current_year = datetime.now().year
    monthly_data = Appointment.objects.filter(doctor=request.user, date__year=current_year).annotate(
        month=TruncMonth('date')
    ).values('month', 'status').annotate(count=Count('id'))

    # Initialize data for each month
    conducted_meetings_data = [0] * 12
    scheduled_meetings_data = [0] * 12
    pending_meetings_data = [0] * 12

    # Populate monthly data
    for entry in monthly_data:
        month_index = entry['month'].month - 1  # Convert month to 0-based index
        if entry['status'] == "conducted":
            conducted_meetings_data[month_index] = entry['count']
        elif entry['status'] == "approved":
            scheduled_meetings_data[month_index] = entry['count']
        elif entry['status'] == "pending":
            pending_meetings_data[month_index] = entry['count']

    context = {
        "conducted_meetings": conducted_meetings,
        "scheduled_meetings": scheduled_meetings,
        "pending_meetings": pending_meetings,
        "conducted_meetings_data": conducted_meetings_data,
        "scheduled_meetings_data": scheduled_meetings_data,
        "pending_meetings_data": pending_meetings_data,
    }
    return render(request, "users/doctor_home.html", context)

@login_required
def patient_home_view(request):
    if request.user.role != "patient":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")

    # Fetch appointment data
    total_appointments = Appointment.objects.filter(patient=request.user).count()
    upcoming_appointments = Appointment.objects.filter(patient=request.user, status="approved").count()
    total_reports = PatientReport.objects.filter(patient=request.user).count()

    # Fetch detailed information about upcoming appointments
    scheduled_meetings = Appointment.objects.filter(
        patient=request.user, 
        status="approved"
    ).select_related('doctor').order_by('date', 'time')

    # Monthly data for line graph
    current_year = datetime.now().year
    monthly_appointments = Appointment.objects.filter(patient=request.user, date__year=current_year).annotate(
        month=TruncMonth('date')
    ).values('month').annotate(count=Count('id'))

    # Initialize data for each month
    monthly_appointments_data = [0] * 12
    for entry in monthly_appointments:
        month_index = entry['month'].month - 1  # Convert month to 0-based index
        monthly_appointments_data[month_index] = entry['count']

    # Appointment status data for pie chart
    completed_appointments = Appointment.objects.filter(patient=request.user, status="completed").count()
    cancelled_appointments = Appointment.objects.filter(patient=request.user, status="cancelled").count()
    appointment_status_data = [completed_appointments, upcoming_appointments, cancelled_appointments]

    context = {
        "total_appointments": total_appointments,
        "upcoming_appointments": upcoming_appointments,
        "scheduled_meetings": scheduled_meetings,  # Add this new variable
        "total_reports": total_reports,
        "monthly_appointments_data": monthly_appointments_data,
        "appointment_status_data": appointment_status_data,
    }
    return render(request, "users/patient_home.html", context)

# Admin home view
@login_required
def admin_home_view(request):
    if request.user.role != "admin":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")
    return render(request, "users/admin_home.html")


# Register view for admin
def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        phone_number = request.POST.get("phone_number")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return render(request, "users/register_admin.html")

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return render(request, "users/register_admin.html")

        if CustomUser.objects.filter(phone_number=phone_number).exists():
            messages.error(request, "Phone number already exists!")
            return render(request, "users/register_admin.html")

        CustomUser.objects.create_user(username=username, password=password, role="admin", phone_number=phone_number)
        messages.success(request, "Admin account created successfully! Please log in.")
        return redirect("login")

    return render(request, "users/register_admin.html")


# Register view for doctors
def register_doctor_view(request):
    if request.method == "POST":
        # If this is OTP verification submission
        if 'verification_id' in request.POST:
            verification_id = request.POST.get('verification_id')
            entered_otp = request.POST.get('otp')
            
            try:
                verification = OTPVerification.objects.get(id=verification_id)
            except OTPVerification.DoesNotExist:
                messages.error(request, "Verification session expired or invalid")
                return render(request, "users/register_doctor.html")
            
            # Verify the OTP
            is_valid, message = verification.verify_otp(entered_otp)
            if not is_valid:
                messages.error(request, message)
                return render(request, "users/verify_otp.html", {
                    'phone_number': verification.phone_number,
                    'verification_id': verification.id
                })
                
            # OTP is valid, register the doctor
            try:
                form_data = json.loads(verification.form_data)
                user = CustomUser.objects.create_user(
                    username=form_data['username'],
                    email=form_data['email'],
                    phone_number=form_data['phone_number'],
                    password=form_data['password'],
                    role="doctor",
                    consultation_fee=0,  # Include this for now
                    is_verified=True
                )
                verification.delete()  # Clean up
                messages.success(request, "Doctor registration successful! Please log in.")
                return redirect("login")
            except Exception as e:
                messages.error(request, f"Registration failed: {str(e)}")
                return render(request, "users/register_doctor.html")
        
        # Initial form submission
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        country_code = request.POST.get("country_code", "+977")  # Default to Nepal if not provided
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        # Basic validations
        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return render(request, "users/register_doctor.html")

        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Invalid email address!")
            return render(request, "users/register_doctor.html")

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return render(request, "users/register_doctor.html")
        
        if email and CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists!")
            return render(request, "users/register_doctor.html")

        # Format phone number with the selected country code
        if not phone_number.startswith('+'):
            formatted_phone = country_code + phone_number.lstrip('0')
        else:
            formatted_phone = phone_number
            
        # No uniqueness check for phone numbers anymore as per your requirement

        # Store form data for OTP verification
        form_data = {
            'username': username,
            'email': email,
            'phone_number': formatted_phone,
            'password': password
        }
        
        # Generate OTP
        otp = OTPVerification.generate_otp()
        expires_at = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
        
        # Create OTP verification record
        verification = OTPVerification.objects.create(
            phone_number=formatted_phone,
            otp_hash=OTPVerification.hash_otp(otp, formatted_phone),
            expires_at=expires_at,
            form_data=json.dumps(form_data),
            registration_type='doctor'  # This indicates it's for doctor registration
        )
        
        # Send OTP via Twilio
        success, message_id = send_otp_sms(formatted_phone, otp)
        
        if success:
            # Show OTP verification page
            return render(request, "users/verify_otp.html", {
                'phone_number': formatted_phone,
                'verification_id': verification.id
            })
        else:
            # If OTP sending fails
            messages.error(request, f"Failed to send verification code: {message_id}")
            verification.delete()  # Clean up the verification entry
            return render(request, "users/register_doctor.html")

    return render(request, "users/register_doctor.html")

# Register view for patient
# Update the register_patient_view in c:\Users\Anish\Desktop\Final Year Project\ehealthcare\users\views.py
import json
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from .models import CustomUser, OTPVerification
from .twilio_utils import send_otp_sms
from django.conf import settings

def register_patient_view(request):
    if request.method == "POST":
        # If this is OTP verification submission
        if 'verification_id' in request.POST:
            verification_id = request.POST.get('verification_id')
            entered_otp = request.POST.get('otp')
            
            try:
                verification = OTPVerification.objects.get(id=verification_id)
            except OTPVerification.DoesNotExist:
                messages.error(request, "Verification session expired or invalid")
                return render(request, "users/register_patient.html")
            
            # Verify the OTP
            is_valid, message = verification.verify_otp(entered_otp)
            if not is_valid:
                messages.error(request, message)
                return render(request, "users/verify_otp.html", {
                    'phone_number': verification.phone_number,
                    'verification_id': verification.id
                })
                
            # OTP is valid, register the user
            try:
                form_data = json.loads(verification.form_data)
                CustomUser.objects.create_user(
                username=form_data['username'],
                email=form_data['email'],
                phone_number=form_data['phone_number'],
                password=form_data['password'],
                role="patient",
                consultation_fee=0,  # Always include this
                is_verified=True
                )
                verification.delete()  # Clean up
                messages.success(request, "Registration successful! Please log in.")
                return redirect("login")
            except Exception as e:
                messages.error(request, f"Registration failed: {str(e)}")
                return render(request, "users/register_patient.html")
        
        # Initial form submission
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        country_code = request.POST.get("country_code", "+977")  # Default to Nepal if not provided
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        # Basic validations
        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return render(request, "users/register_patient.html")

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return render(request, "users/register_patient.html")
        
        if email and CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists!")
            return render(request, "users/register_patient.html")

        # Format phone number with the selected country code
        if not phone_number.startswith('+'):
            formatted_phone = country_code + phone_number.lstrip('0')
        else:
            formatted_phone = phone_number
        
        # Country code aware phone number validation
        # Check if this phone number exists with the same country code
        if CustomUser.objects.filter(phone_number=formatted_phone).exists():
            messages.error(request, f"Phone number already exists with country code {country_code}!")
            return render(request, "users/register_patient.html")

        # Store form data for OTP verification
        form_data = {
            'username': username,
            'email': email,
            'phone_number': formatted_phone,
            'password': password
        }
        
        # Generate OTP
        otp = OTPVerification.generate_otp()
        expires_at = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
        
        # Create OTP verification record
        verification = OTPVerification.objects.create(
            phone_number=formatted_phone,
            otp_hash=OTPVerification.hash_otp(otp, formatted_phone),
            expires_at=expires_at,
            form_data=json.dumps(form_data),
            registration_type='patient'
        )
        
        # Send OTP via Twilio
        success, message_id = send_otp_sms(formatted_phone, otp)
        
        if success:
            # Show OTP verification page
            return render(request, "users/verify_otp.html", {
                'phone_number': formatted_phone,
                'verification_id': verification.id
            })
        else:
            # If OTP sending fails
            messages.error(request, f"Failed to send verification code: {message_id}")
            verification.delete()  # Clean up the verification entry
            return render(request, "users/register_patient.html")

    return render(request, "users/register_patient.html")

@login_required
def patient_medical_reports_view(request):
    if request.user.role != "patient":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")
    return render(request, "users/patient_medical_reports.html")

@login_required
def upload_patient_report_view(request):
    if request.user.role != "patient":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")

    if request.method == "POST":
        report_type = request.POST.get("report_type", "other")  # Default to "other" if not provided
        files = request.FILES.getlist("files")  # Get all uploaded files

        if not files:
            messages.error(request, "No files selected for upload.")
            return redirect("patient_medical_reports")

        for file in files:
            # Create a new PatientReport instance for each file
            PatientReport.objects.create(
                patient=request.user,
                file=file,
                report_type=report_type,
            )

        messages.success(request, f"{len(files)} {report_type.capitalize()} report(s) uploaded successfully!")
        return redirect("patient_medical_reports")

    messages.error(request, "Failed to upload the report(s). Please try again.")
    return redirect("patient_medical_reports")

@login_required
def view_all_reports(request):
    if request.user.role != "patient":
        return JsonResponse({"error": "Unauthorized access"}, status=403)

    # Fetch all reports for the logged-in patient, grouped by report type
    reports = {
        "video": list(PatientReport.objects.filter(patient=request.user, report_type="video").values("id", "file", "uploaded_at")),
        "lab": list(PatientReport.objects.filter(patient=request.user, report_type="lab").values("id", "file", "uploaded_at")),
        "other": list(PatientReport.objects.filter(patient=request.user, report_type="other").values("id", "file", "uploaded_at")),
    }
    return JsonResponse(reports)

import logging
logger = logging.getLogger(__name__)

@login_required
def delete_report(request, report_id):
    if request.user.role != "patient":
        return JsonResponse({"error": "Unauthorized access"}, status=403)

    try:
        report = PatientReport.objects.get(id=report_id, patient=request.user)
        report.delete()
        logger.info(f"Report with ID {report_id} deleted by user {request.user.username}")
        return JsonResponse({"success": "Report deleted successfully!"})
    except PatientReport.DoesNotExist:
        logger.warning(f"Attempt to delete non-existent or unauthorized report with ID {report_id} by user {request.user.username}")
        return JsonResponse({"error": "Report not found or unauthorized access"}, status=404)

@login_required
def doctor_medical_reports_view(request):
    if request.user.role != "doctor":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("doctor_home")
    return render(request, "users/doctor_medical_reports.html")

@login_required
def doctor_medical_reports_view(request):
    if request.user.role != "doctor":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("doctor_home")

    if request.method == "POST":
        report_type = request.POST.get("report_type", "other")
        files = request.FILES.getlist("files")

        if not files:
            messages.error(request, "No files selected for upload.")
            return redirect("doctor_medical_reports")

        for file in files:
            DoctorReport.objects.create(
                doctor=request.user,
                file=file,
                report_type=report_type,
            )

        messages.success(request, f"{len(files)} {report_type.capitalize()} report(s) uploaded successfully!")
        return redirect("doctor_medical_reports")

    reports = {
        "video": DoctorReport.objects.filter(doctor=request.user, report_type="video"),
        "lab": DoctorReport.objects.filter(doctor=request.user, report_type="lab"),
        "other": DoctorReport.objects.filter(doctor=request.user, report_type="other"),
    }

    return render(request, "users/doctor_medical_reports.html", {"reports": reports})


@login_required
def fetch_doctor_reports(request):
    if request.user.role != "doctor":
        return JsonResponse({"error": "Unauthorized access"}, status=403)

    # Fetch all reports for the logged-in doctor, grouped by report type
    reports = {
        "video": list(DoctorReport.objects.filter(doctor=request.user, report_type="video").values("id", "file", "uploaded_at")),
        "lab": list(DoctorReport.objects.filter(doctor=request.user, report_type="lab").values("id", "file", "uploaded_at")),
        "other": list(DoctorReport.objects.filter(doctor=request.user, report_type="other").values("id", "file", "uploaded_at")),
    }
    return JsonResponse(reports)
@login_required
def delete_doctor_report(request, report_id):
    if request.user.role != "doctor":
        return JsonResponse({"error": "Unauthorized access"}, status=403)

    try:
        report = DoctorReport.objects.get(id=report_id, doctor=request.user)
        report.delete()
        return JsonResponse({"success": "Report deleted successfully!"})
    except DoctorReport.DoesNotExist:
        return JsonResponse({"error": "Report not found or unauthorized access"}, status=404)

@login_required
def patient_appointment_view(request):
    if request.user.role != "patient":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")

    if request.method == "POST":
        doctor_id = request.POST.get("doctor_id")
        date = request.POST.get("date")
        time = request.POST.get("time")

        try:
            doctor = CustomUser.objects.get(id=doctor_id, role="doctor")
            
            # Check for double booking
            existing_appointment = Appointment.objects.filter(
                doctor=doctor,
                date=date,
                time=time
            ).exists()
            
            if existing_appointment:
                messages.error(request, "Sorry, this time slot has just been booked by another patient. Please select another time.")
            else:
                # Create the appointment since the slot is available
                Appointment.objects.create(
                    patient=request.user,
                    doctor=doctor,
                    date=date,
                    time=time,
                )
                messages.success(request, "Appointment request sent successfully!")
                
        except CustomUser.DoesNotExist:
            messages.error(request, "Invalid doctor selected.")

    # Fetch all registered doctors for the dropdown
    doctors = CustomUser.objects.filter(role="doctor")

    return render(request, "users/patient_appointment.html", {"doctors": doctors})

@login_required
def doctor_appointment_view(request):
    if request.user.role != "doctor":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")

    # Fetch all appointments for the logged-in doctor
    appointments = Appointment.objects.filter(doctor=request.user).order_by("date", "time")

    return render(request, "users/doctor_appointment.html", {"appointments": appointments})

@login_required
def start_meeting(request, appointment_id):
    if request.user.role != "doctor":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("doctor_home")

    try:
        appointment = Appointment.objects.get(id=appointment_id, doctor=request.user)
        # Allow starting meetings for approved appointments
        if appointment.status == "approved":
            room_name = f"room-{appointment_id}"
            return redirect("video_conference", room_name=room_name)
        elif appointment.status == "pending":
            # Auto-approve pending appointments when starting
            appointment.status = "approved"
            appointment.save()
            room_name = f"room-{appointment_id}"
            return redirect("video_conference", room_name=room_name)
        else:
            messages.error(request, "This appointment cannot be started in its current state.")
    except Appointment.DoesNotExist:
        messages.error(request, "Appointment not found.")

    return redirect("doctor_appointment")

@login_required
def schedule_meeting(request):
    if request.user.role != "doctor":
        return JsonResponse({"error": "Unauthorized access"}, status=403)

    if request.method == "POST":
        try:
            patient_id = request.POST.get("patient_id")
            meeting_date = request.POST.get("meeting_date")
            meeting_time = request.POST.get("meeting_time")
            meeting_title = request.POST.get("meeting_title")
            is_recurring = request.POST.get("is_recurring") == "on"
            
            # Validate inputs
            if not patient_id or not meeting_date or not meeting_time:
                return JsonResponse({"error": "Missing required fields"}, status=400)
                
            # Get the patient
            try:
                patient = CustomUser.objects.get(id=patient_id, role="patient")
            except CustomUser.DoesNotExist:
                return JsonResponse({"error": "Patient not found"}, status=404)
            
            # Create the appointment
            appointment = Appointment.objects.create(
                doctor=request.user,
                patient=patient,
                date=meeting_date,
                time=meeting_time,
                title=meeting_title or f"Appointment with {patient.username}",
                status="approved",  # Auto-approve since doctor initiated
                is_recurring=is_recurring
            )
            
            return JsonResponse({
                "success": f"Meeting scheduled successfully with {patient.username}!",
                "appointment_id": appointment.id
            })
            
        except Exception as e:
            return JsonResponse({"error": f"Failed to schedule meeting: {str(e)}"}, status=500)
            
    return JsonResponse({"error": "Invalid request method"}, status=400)

@login_required
def doctor_appointment_view(request):
    if request.user.role != "doctor":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")

    # Fetch all appointments for the logged-in doctor
    appointments = Appointment.objects.filter(doctor=request.user).order_by("date", "time")
    
    # Get all patients to populate the dropdown
    patients = CustomUser.objects.filter(role="patient")

    return render(request, "users/doctor_appointment.html", {
        "appointments": appointments,
        "patients": patients
    })

@login_required
def video_conference_view(request, room_name):
    return render(request, "users/video_conference.html", {
        "room_name": room_name,
        "username": request.user.username,
    })

@login_required
def delete_meeting(request, appointment_id):
    if request.user.role != "doctor":
        return JsonResponse({"error": "Unauthorized access"}, status=403)

    try:
        appointment = Appointment.objects.get(id=appointment_id, doctor=request.user)
        appointment.delete()
        return JsonResponse({"success": "Meeting deleted successfully!"})
    except Appointment.DoesNotExist:
        return JsonResponse({"error": "Meeting not found"}, status=404)

@login_required
def mark_meeting_conducted(request, appointment_id):
    if request.user.role != "doctor":
        return JsonResponse({"error": "Unauthorized access"}, status=403)

    try:
        appointment = Appointment.objects.get(id=appointment_id, doctor=request.user)
        appointment.status = "conducted"
        appointment.save()
        return JsonResponse({"success": "Meeting marked as conducted successfully!"})
    except Appointment.DoesNotExist:
        return JsonResponse({"error": "Meeting not found"}, status=404)
    
@login_required
def approve_appointment(request, appointment_id):
    if request.user.role != "doctor":
        return JsonResponse({"error": "Unauthorized access"}, status=403)

    try:
        appointment = Appointment.objects.get(id=appointment_id, doctor=request.user)
        if appointment.status == "pending":
            appointment.status = "approved"
            appointment.save()
            return JsonResponse({"success": "Appointment approved successfully!"})
        else:
            return JsonResponse({"error": "This appointment is not in a pending state."}, status=400)
    except Appointment.DoesNotExist:
        return JsonResponse({"error": "Appointment not found"}, status=404)

# Add this function to c:\Users\Anish\Desktop\Final Year Project\ehealthcare\users\views.py
def resend_otp_view(request, verification_id):
    try:
        verification = OTPVerification.objects.get(id=verification_id)
    except OTPVerification.DoesNotExist:
        messages.error(request, "Invalid verification session")
        return redirect('register_patient')
    
    # Check resend limits
    if verification.resend_count >= settings.OTP_RESEND_LIMIT:
        messages.error(request, f"Maximum resend limit reached ({settings.OTP_RESEND_LIMIT} attempts)")
        return render(request, "users/verify_otp.html", {
            'phone_number': verification.phone_number,
            'verification_id': verification_id
        })
    
    # Check timeframe
    time_since_first = timezone.now() - verification.first_sent_at
    if time_since_first > timedelta(minutes=settings.OTP_RESEND_TIMEFRAME_MINUTES):
        # Reset if outside timeframe
        verification.resend_count = 0
        verification.first_sent_at = timezone.now()
    
    # Generate new OTP
    new_otp = OTPVerification.generate_otp()
    verification.otp_hash = OTPVerification.hash_otp(new_otp, verification.phone_number)
    verification.expires_at = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
    verification.last_sent_at = timezone.now()
    verification.resend_count += 1
    verification.attempts = 0
    verification.save()
    
    # Send new OTP
    success, message_id = send_otp_sms(verification.phone_number, new_otp)
    
    if success:
        messages.success(request, "New verification code sent!")
    else:
        messages.error(request, f"Failed to send verification code: {message_id}")
    
    return render(request, "users/verify_otp.html", {
        'phone_number': verification.phone_number,
        'verification_id': verification_id
    })

# Add this function to c:\Users\Anish\Desktop\Final Year Project\ehealthcare\users\views.py
def verify_otp_view(request):
    if request.method != "POST":
        return redirect('login')
        
    verification_id = request.POST.get('verification_id')
    entered_otp = request.POST.get('otp')
    
    if not verification_id or not entered_otp:
        messages.error(request, "Invalid verification request")
        return redirect('login')
    
    try:
        verification = OTPVerification.objects.get(id=verification_id)
    except OTPVerification.DoesNotExist:
        messages.error(request, "Verification session expired or invalid")
        return redirect('login')
    
    # Verify OTP
    is_valid, message = verification.verify_otp(entered_otp)
    if not is_valid:
        messages.error(request, message)
        return render(request, "users/verify_otp.html", {
            'phone_number': verification.phone_number,
            'verification_id': verification.id
        })
    
    # OTP is valid, register the user based on registration type
    try:
        form_data = json.loads(verification.form_data)
        
        if verification.registration_type == 'patient':
            CustomUser.objects.create_user(
                username=form_data['username'],
                email=form_data['email'],
                phone_number=form_data['phone_number'],
                password=form_data['password'],
                role="patient",
                consultation_fee=0,
                is_verified=True  # Add this line
            )
        elif verification.registration_type == 'doctor':
            CustomUser.objects.create_user(
                username=form_data['username'],
                email=form_data['email'],
                phone_number=form_data['phone_number'],
                password=form_data['password'],
                role="doctor", 
                consultation_fee=0,
                is_verified=True  # Add this line
            )
        elif verification.registration_type == 'admin':
            CustomUser.objects.create_user(
                username=form_data['username'],
                email=form_data.get('email', ''),
                phone_number=form_data['phone_number'],
                password=form_data['password'],
                role="admin",
                consultation_fee=0,
                is_verified=True  # Add this line
            )
        
        # Clean up
        verification.delete()
        
        messages.success(request, f"{verification.registration_type.capitalize()} account created successfully! Please log in.")
        return redirect('login')
        
    except Exception as e:
        messages.error(request, f"Registration failed: {str(e)}")
        return redirect('login')

def is_phone_number_taken(formatted_phone):
    """
    Allow any phone number to be used multiple times, regardless of country code
    """
    return False  # Always allow the phone number to be used

# Add these two view functions after your other doctor-related views
@login_required
def doctor_availability_view(request):
    """Get doctor's availability settings"""
    if request.user.role != "doctor":
        return JsonResponse({"error": "Unauthorized access"}, status=403)
        
    availability = {}
    # Initialize all days with empty lists
    for day in range(6):  # 0 (Sunday) to 5 (Friday)
        availability[str(day)] = []
        
    # Get doctor's saved availability
    slots = DoctorAvailability.objects.filter(doctor=request.user)
    for slot in slots:
        day = str(slot.day_of_week)
        if day not in availability:
            availability[day] = []
            
        availability[day].append({
            "id": slot.id,
            "start_time": slot.start_time.strftime("%H:%M"),
            "end_time": slot.end_time.strftime("%H:%M")
        })
    
    return JsonResponse(availability)

@login_required
def save_availability_view(request):
    """Save doctor's availability settings"""
    if request.user.role != "doctor":
        return JsonResponse({"error": "Unauthorized access"}, status=403)
    
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=400)
    
    try:
        data = json.loads(request.body)
        
        # Delete existing availability
        DoctorAvailability.objects.filter(doctor=request.user).delete()
        
        # Create new availability slots
        for day, slots in data.items():
            day = int(day)  # Convert string key to int
            for slot in slots:
                DoctorAvailability.objects.create(
                    doctor=request.user,
                    day_of_week=day,
                    start_time=slot['start_time'],
                    end_time=slot['end_time']
                )
        
        return JsonResponse({"success": True})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

# Add this function to fetch available slots for patients
@login_required
def get_doctor_available_slots(request, doctor_id, date):
    """Get available time slots for a doctor on a specific date"""
    try:
        # Get the day of week (0=Sunday, 6=Saturday)
        selected_date = datetime.strptime(date, "%Y-%m-%d")
        day_of_week = selected_date.weekday()
        
        # Convert Monday-based to Sunday-based (Django is Monday=0, we use Sunday=0)
        day_of_week = 0 if day_of_week == 6 else day_of_week + 1
        
        # Saturday is off
        if day_of_week == 6:
            return JsonResponse({"available_slots": []})
            
        doctor = CustomUser.objects.get(id=doctor_id, role="doctor")
        availability = DoctorAvailability.objects.filter(doctor=doctor, day_of_week=day_of_week)
        
        # Format slots
        slots = []
        for slot in availability:
            start = slot.start_time
            end = slot.end_time
            
            # Create 30 min intervals
            while start < end:
                next_slot = (datetime.combine(datetime.today(), start) + timedelta(minutes=30)).time()
                if next_slot <= end:
                    slots.append({
                        "start": start.strftime("%H:%M"),
                        "end": next_slot.strftime("%H:%M")
                    })
                start = next_slot
                
        # Remove booked slots - ensure consistent formatting
        booked_appointments = Appointment.objects.filter(
            doctor=doctor, 
            date=selected_date
        )
        
        booked_times = []
        for appointment in booked_appointments:
            # Get time as "HH:MM" format to match slot["start"]
            booked_time = appointment.time
            if isinstance(appointment.time, str):
                booked_times.append(appointment.time)
            else:
                # If it's a datetime.time object
                booked_times.append(appointment.time.strftime("%H:%M"))
        
        available_slots = [slot for slot in slots if slot["start"] not in booked_times]
        
        return JsonResponse({"available_slots": available_slots})
    except CustomUser.DoesNotExist:
        return JsonResponse({"error": "Doctor not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)