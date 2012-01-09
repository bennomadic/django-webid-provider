from django.conf.urls.defaults import *
from django.views.generic.simple import direct_to_template, redirect_to

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    (r'^admin/', include(admin.site.urls)),
    (r'^webid/', include('django_webid.provider.urls')),
    (r'^$', direct_to_template, {'template': 'django_webid/provider/webid_index.html'}),

    #REGISTRATION URLS
    #(r'^accounts/', include('registration.backends.default.urls')),
    (r'^accounts/', include('registration.urls')),

    # until we implement profiles view
    # we have this redirect for the sample site.
    (r'^accounts/profile', redirect_to, {'url':'/'}),
)
