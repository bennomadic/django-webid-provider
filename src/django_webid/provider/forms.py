from django import forms
from django.utils.safestring import mark_safe

class CharNotEditableWidget(forms.Widget):
    def render(self, name, value, attrs):
        final_attrs = self.build_attrs(attrs, name=name)
        if hasattr(self, 'initial'):
            value = self.initial
        return mark_safe(
            "@%s" % (
                value
            )
        )
    def _has_changed(self, initial, data):
        return False

class WebIdIdentityForm(forms.Form):
    nick = forms.CharField(max_length=10)
    webid = forms.URLField(required=False)
