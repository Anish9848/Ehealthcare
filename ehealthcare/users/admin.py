from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, PatientReport, DoctorReport, Appointment, OTPVerification

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'phone_number', 'role', 'is_active', 'date_joined')
    list_filter = ('role', 'is_active', 'date_joined')
    search_fields = ('username', 'email', 'phone_number')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'email', 'phone_number')}),
        ('E-Healthcare Info', {'fields': ('role', 'consultation_fee')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'phone_number', 'role', 'password1', 'password2'),
        }),
    )
    
    actions = ['make_active', 'make_inactive']
    
    def make_active(self, request, queryset):
        queryset.update(is_active=True)
    make_active.short_description = "Mark selected users as active"
    
    def make_inactive(self, request, queryset):
        queryset.update(is_active=False)
    make_inactive.short_description = "Mark selected users as inactive"

@admin.register(Appointment)
class AppointmentAdmin(admin.ModelAdmin):
    list_display = ('patient', 'doctor', 'date', 'time', 'status', 'created_at')
    list_filter = ('status', 'date', 'created_at')
    search_fields = ('patient__username', 'doctor__username')
    date_hierarchy = 'date'

@admin.register(PatientReport)
class PatientReportAdmin(admin.ModelAdmin):
    list_display = ('patient', 'report_type', 'uploaded_at')
    list_filter = ('report_type', 'uploaded_at')
    search_fields = ('patient__username',)

@admin.register(DoctorReport)
class DoctorReportAdmin(admin.ModelAdmin):
    list_display = ('doctor', 'report_type', 'uploaded_at')
    list_filter = ('report_type', 'uploaded_at')
    search_fields = ('doctor__username',)

@admin.register(OTPVerification)
class OTPVerificationAdmin(admin.ModelAdmin):
    list_display = ('phone_number', 'registration_type', 'attempts', 'is_verified', 'expires_at')
    list_filter = ('registration_type', 'is_verified')
    search_fields = ('phone_number',)
    readonly_fields = ('otp_hash', 'form_data')