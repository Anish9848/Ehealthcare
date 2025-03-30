from django import forms
from .models import PatientReport

class PatientReportForm(forms.ModelForm):
    class Meta:
        model = PatientReport
        fields = ['file']