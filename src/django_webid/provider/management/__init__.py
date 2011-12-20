from django.db.models.signals import post_syncdb
from django_webid.provider import models as webidprovider_app

from .certconfig_defaults import set_defaultsettings

post_syncdb.connect(set_defaultsettings, sender=webidprovider_app)
