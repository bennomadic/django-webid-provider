from django_webid.provider.models import CertConfig
from django_webid.provider import provider_settings as app_settings

#site-wide django settings conf is parsed
#in webidprovider_settings, and there a sensible default is provided.

def set_defaultsettings(sender, **kwargs):

    dc = CertConfig()
    dc_dict = app_settings.CertDefaultsWrapper()
    for field, value in dc_dict.items():
        setattr(dc, field, value)
    dc.save()
