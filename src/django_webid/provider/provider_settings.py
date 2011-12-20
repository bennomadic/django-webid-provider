from django.conf import settings

#THIS IS THE DEFAULTS DICT FOR CERTCONFIG and app-wide
#behaviors.
#DO NOT change them here: use the site-wide settings file
#or change them in the CertConfig Admin interface.

SENSIBLE_DEFAULTS = {
        #subject name
        "CERT_C": ("country_name", "CC"),
        "CERT_ST": ("state", "Cyberspace"),
        "CERT_L": ("locality", "/dev/null"),
        "CERT_O": ("organization", "FOAF+SSL"),
        "CERT_OU": ("organizational_unit", "The Community of Self Signers"),
        #name field
        "CERT_CN" : ("common_name_field", "username"),
        #validity
        "CERT_VALID_FOR_DAYS": ("valid_for_days", 365),
        "CERT_VALID_FROM_DAYS": ("valid_from_days", 0)
}

APP_NAME = "WEBID_PROVIDER"

#XXX TODO
#Document in sphinx docs all the possible default settings WEBID_PROVIDER_XXX

class CertDefaultsWrapper(dict):
    def __init__(self):
        for cert_field, (model_field, default) in SENSIBLE_DEFAULTS.items():
            self[model_field] = getattr(settings,
            "%s_%s" % (APP_NAME, cert_field),
            default)


