from django.conf.urls.defaults import *
from django.views.generic.simple import direct_to_template

from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    (r'^admin/', include(admin.site.urls)),
    (r'^webid/', include('django_webid.provider.urls')),
    (r'^$', direct_to_template, {'template': 'django_webid/provider/webid_index.html'}),
)
