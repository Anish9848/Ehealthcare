from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from .models import CustomUser, PatientReport  # Import both models
from django.core.files.storage import FileSystemStorage
from .forms import PatientReportForm
from django.http import JsonResponse
from .models import CustomUser, PatientReport, DoctorReport, Appointment

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
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

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

        if CustomUser.objects.filter(phone_number=phone_number).exists():
            messages.error(request, "Phone number already exists!")
            return render(request, "users/register_doctor.html")

        CustomUser.objects.create_user(username=username, email=email, password=password, role="doctor", phone_number=phone_number)
        messages.success(request, "Doctor account created successfully! Please log in.")
        return redirect("login")

    return render(request, "users/register_doctor.html")

# Register view for patient

def register_patient_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return render(request, "users/register_patient.html")

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return render(request, "users/register_patient.html")

        if CustomUser.objects.filter(phone_number=phone_number).exists():
            messages.error(request, "Phone number already exists!")
            return render(request, "users/register_patient.html")

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists!")
            return render(request, "users/register_patient.html")

        # Create the patient user directly
        CustomUser.objects.create_user(
            username=username,
            email=email,
            phone_number=phone_number,
            password=password,
            role="patient",
        )
        messages.success(request, "Patient account created successfully! Please log in.")
        return redirect("login")

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
        "video": list(PatientReport.objects.filter(patient=request.user, report_type="video").values("file", "uploaded_at")),
        "lab": list(PatientReport.objects.filter(patient=request.user, report_type="lab").values("file", "uploaded_at")),
        "other": list(PatientReport.objects.filter(patient=request.user, report_type="other").values("file", "uploaded_at")),
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
        if appointment.status == "pending":
            appointment.status = "approved"
            appointment.save()
            room_name = f"room-{appointment_id}"  # Ensure this matches the frontend
            return redirect("video_conference", room_name=room_name)
        else:
            messages.error(request, "This appointment is not in a pending state.")
    except Appointment.DoesNotExist:
        messages.error(request, "Appointment not found.")

    return redirect("doctor_appointment")

@login_required
def schedule_meeting(request):
    if request.user.role != "doctor":
        return JsonResponse({"error": "Unauthorized access"}, status=403)

    if request.method == "POST":
        meeting_date = request.POST.get("meeting_date")
        meeting_time = request.POST.get("meeting_time")
        meeting_title = request.POST.get("meeting_title")
        is_recurring = request.POST.get("is_recurring") == "true"

        # Logic to save the meeting details
        # Example: Save to the database or update an appointment
        # You can customize this logic based on your requirements

        return JsonResponse({"success": "Meeting scheduled successfully!"})
    return JsonResponse({"error": "Invalid request method"}, status=400)

@login_required
def doctor_appointment_view(request):
    if request.user.role != "doctor":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")

    # Fetch all appointments for the logged-in doctor
    appointments = Appointment.objects.filter(doctor=request.user).order_by("date", "time")

    return render(request, "users/doctor_appointment.html", {"appointments": appointments})

@login_required
def video_conference_view(request, room_name):
    return render(request, "users/video_conference.html", {
        "room_name": room_name,
        "username": request.user.username,
    })