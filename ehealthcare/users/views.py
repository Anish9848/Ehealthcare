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
from .models import CustomUser, PatientReport, DoctorReport

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
@login_required
def doctor_home_view(request):
    if request.user.role != "doctor":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")
    return render(request, "users/doctor_home.html")


# Patient home view
@login_required
def patient_home_view(request):
    if request.user.role != "patient":
        messages.error(request, "You do not have permission to access this page.")
        return redirect("home")
    return render(request, "users/patient_home.html")


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


