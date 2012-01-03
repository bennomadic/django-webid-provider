from django.conf.urls.defaults import *
from django.views.generic.simple import redirect_to
from django_webid.provider import views, webiduri

urlpatterns = patterns('',
    #Main, WORKING urls

    #temporary REDIRECT
    #XXX we need a info page here
    url(r'^$', redirect_to, {'url':'cert/add'}),

    url(r'^cert/add$', views.add_cert_to_user, name="webidprovider-add_cert"),
    url(r'^user/add$', views.create_user, name='webidprovider-create_user'),

    #WebID Profile / Foaf publishing...
    #XXX can we do some magic here? (asking settings, finstance)
    #XXX should be "%s/foo" % settings.WEBID_PATH
    #XXX We MUST allow for other app to take control of this
    #XXX but at the same time provide a fallback mechanism...

    url(r'^(?P<username>\w+)$',
        webiduri.WebIDProfileView.as_view(), name="webidprovider-webid_uri"),

    ################################################
    ################################################
    # Other tests: to be cleaned from here...
    # Might be BROKEN

    url(r'^cert/p12/add$', views.webid_identity,
        name='webidprovider-webid_identity1'),
    url(r'^cert/keygen$', views.webid_identity_keygen,
        name='webidprovider-webid_identity_keygen'),

)
