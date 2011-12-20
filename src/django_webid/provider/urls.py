from django.conf.urls.defaults import *

urlpatterns = patterns('',
    #Main, WORKING urls

    url(r'^addcert$',
        'django_webid.provider.views.add_cert_to_user',
        name="add_cert_to_user"),
    url(r'^create$',
        'django_webid.provider.views.create_user',
        name='create_user'),
    url(r'^$',
        'django_webid.provider.views.add_cert_to_user',
        name="add_cert_to_user1"),

    #Foaf publishing...
    #XXX can we do some magic here? (asking settings, finstance)

    url(r'^foaf/(?P<username>\w+)/$',
        #XXX should be "%s/foo" % settings.WEBID_PATH
        #with a sensible default...
        'django_webid.provider.views.render_webid',
        name="webid_uri"),

    ################################################
    ################################################
    # Other tests: to be cleaned from here...
    # Might be BROKEN

    url(r'^createp12$', 'django_webid.provider.views.webid_identity',
        name='webid_identity1'),
    url(r'^webidkeygen$',
        'django_webid.provider.views.webid_identity_keygen',
        name='webid_identity_keygen'),

)
