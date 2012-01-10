from django.conf.urls.defaults import *
from django.views.generic.simple import redirect_to
from django.views.generic.list_detail import object_list
from django_webid.provider import views, webiduri
from django_webid.provider.models import Cert

urlpatterns = patterns('',
    #Main, WORKING urls

    #temporary REDIRECT
    # XXX move to the sample project
    url(r'^$', redirect_to, {'url':'cert/add'}),
    url(r'^logout$', views.logout_view, name="webidprovider-logout"),

    ###################################
    #BEGIN django_webid.provider views

    #certs/all/ --> take all objects from pubkey manager (currently should
    #be only active)
    url(r'^certs$', views.cert_list_by_user, name="webidprovider-cert_list"),
    url(r'^cert/add$', views.add_cert_to_user, name="webidprovider-add_cert"),
    url(r'^cert/(?P<cert_id>\d+)/$', views.cert_detail,
        name="webidprovider-cert-detail"),
    url(r'^cert/(?P<cert_id>\d+)/revoke$', views.cert_revoke,
        name="webidprovider-cert-revoke"),

    #Our simple user creation view.
    #XXX we should move it to example site too.
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
    # Some other, older tests: to be cleaned from here...
    # Might be BROKEN

    url(r'^cert/p12/add$', views.webid_identity,
        name='webidprovider-webid_identity1'),
    url(r'^cert/keygen$', views.webid_identity_keygen,
        name='webidprovider-webid_identity_keygen'),

)
