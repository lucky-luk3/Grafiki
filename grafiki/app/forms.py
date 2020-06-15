from django import forms
from .models import File, Example

class FileForm(forms.ModelForm):
    class Meta:
        model = File
        fields = ('name', 'evtx')


class ExampleForm(forms.ModelForm):

    class Meta:
        model = Example
        fields = ['name', 'category', 'url', 'source']

    def __init__(self, *args, **kwargs):
        super(ExampleForm, self).__init__(*args, **kwargs)
        for field in iter(self.fields):
                self.fields[field].widget.attrs.update({
                    'class': 'form-control'
                })

class DateForm(forms.Form):
    date = forms.DateTimeField(
        input_formats=['%d/%m/%Y %H:%M'],
        widget=forms.DateTimeInput(attrs={
            'class': 'form-control datetimepicker-input',
            'data-target': '#from'
        })
    )