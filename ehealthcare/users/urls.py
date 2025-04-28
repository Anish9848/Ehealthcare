from django.urls import path
from . import views

urlpatterns = [
    path("", views.login_view, name="login"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("register/doctor/", views.register_doctor_view, name="register_doctor"),
    path("register/patient/", views.register_patient_view, name="register_patient"),
    path("register/admin/", views.register_view, name="register_admin"),
    path("doctor/home/", views.doctor_home_view, name="doctor_home"),
    path("patient/home/", views.patient_home_view, name="patient_home"),
    path("admin/home/", views.admin_home_view, name="admin_home"),
    path("patient/reports/", views.patient_medical_reports_view, name="patient_medical_reports"),
    path("patient/reports/upload/other/", views.upload_patient_report_view, name="upload_patient_report"),
    path("patient/reports/all/", views.view_all_reports, name="view_all_reports"),
    path("patient/reports/delete/<int:report_id>/", views.delete_report, name="delete_report"),
    path("doctor/reports/", views.doctor_medical_reports_view, name="doctor_medical_reports"),
    path("doctor/reports/fetch/", views.fetch_doctor_reports, name="fetch_doctor_reports"),
    path("doctor/reports/delete/<int:report_id>/", views.delete_doctor_report, name="delete_doctor_report"),
    path("patient/appointments/", views.patient_appointment_view, name="patient_appointment"),
    path("doctor/appointments/", views.doctor_appointment_view, name="doctor_appointment"),
    path("doctor/appointments/start-meeting/<int:appointment_id>/", views.start_meeting, name="start_meeting"),
    path("doctor/appointments/schedule-meeting/", views.schedule_meeting, name="schedule_meeting"),
    path("video-conference/<str:room_name>/", views.video_conference_view, name="video_conference"),
    path("doctor/appointments/delete-meeting/<int:appointment_id>/", views.delete_meeting, name="delete_meeting"),
    path("doctor/appointments/mark-conducted/<int:appointment_id>/", views.mark_meeting_conducted, name="mark_meeting_conducted"),
]