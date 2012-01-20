from django.db import models

from django.contrib.auth.models import User
from django.contrib.sites.models import Site

from django.core.urlresolvers import reverse
#from django.utils.translation import gettext as _


class SingletonManager(models.Manager):
    def single(self):
        return self.all()[0]


class CertConfig(models.Model):
    """
    this model stores several defaults used
    in the certificate creation.
    values can be changed by site admin.
    On syncdb it is populated from settings, falling
    back to a certain set of defaults.
    This model behaves as a singleton: its admin
    does not allow adding or deleting the single instance.
    """

    #Defaults for App Behavior
    hide_keygen_form = models.BooleanField(default=False,
    help_text="WebID Certificate Add Page will hide keygen \
details from user, giving the impression of an automatic certificate \
installation")

    #Defaults for subject

    #XXX should be choices from ISO-2 country codes.
    country_name = models.CharField(null=True, blank=True, max_length=2,
            help_text="Country Name (2 letter code)")
    state = models.CharField(null=True, blank=True, max_length=255,
            help_text="State or Province")
    locality = models.CharField(null=True, blank=True, max_length=255)
    organization = models.CharField(null=True, blank=True, max_length=255,
            help_text="Organization Name")
    organizational_unit = models.CharField(null=True, blank=True,
            max_length=255,
            help_text="Organizational Unit Name")

    #XXX TBD.. We can mark here a gfk to contenttypes
    #so site admin can decide which field goes
    #into the common name.
    #RIGHT NOW XXX THIS IS QUITE PRONE TO MISTAKES :(
    common_name_field = models.CharField(default="nick", max_length=255,
        help_text="User Field to be\
        used in the Certificate's Subject Common Name")

    #XXX Actually in the future,
    #it would make sense to eval all the other fields
    #(admin can decide to map the value of the certificate on some fields to
    #user-related fields
    #in the database.

    #Defaults for validity
    valid_for_days = models.IntegerField(help_text="How many days will the\
        certificate be valid")
    valid_from_days = models.IntegerField(help_text="How many days, starting\
        with the cert creation, until the certificate is active")

    def get_subject_data(self):
        """
        helper methods for certificate creation.
        returns a dict with cert subject codes
        and field values
        """
        data = {}
        attrs = (('C', 'country_name'),
                 ('ST', 'state'),
                 ('L', 'locality'),
                 ('O', 'organization'),
                 ('OU', 'organizational_unit'))
        for code, field_name in attrs:
            val = getattr(self, field_name, None)
            if val:
                data[code] = val
        return data

    def get_common_name_field(self):
        return self.common_name_field

    def get_validity(self):
        data = {"for_days": self.valid_for_days,
                "from_days": self.valid_from_days}
        return data

    #currently using a hack: see Admin no-add/no-edit restriction
    #we can decide whether it makes sense having a per-site config section
    #or not...

    objects = SingletonManager()

    class Meta:
        verbose_name = "Default Certificate Values"
        verbose_name_plural = "Default Certificate Values"
        db_table = "webid_provider_certconfig"

    def __unicode__(self):
        return "Default Configuration for WebID Certificates"


class ActivePubKeyManager(models.Manager):
    """
    default manager for PubKey. returns only
    the PubKeys with is_active = True
    """
    def get_query_set(self):
        return super(ActivePubKeyManager,
                self).get_query_set().filter(is_active=True)


class PubKey(models.Model):
    #XXX in admin, should use inline
    #for viewing the cert at the same time.

    mod = models.CharField(max_length=10000)
    exp = models.IntegerField()
    bits = models.IntegerField()

    #choices?
    pkey_algorithm = models.CharField(blank=True, max_length=255)
    is_active = models.BooleanField(default=True)

    created = models.DateTimeField(blank=True)

    user = models.ForeignKey(User)

    #we preserve the original manager
    objects = models.Manager()
    #we only count the active PubKeys
    active_objects = ActivePubKeyManager()

    @property
    def date_created(self):
        return self.created.strftime('%m/%d/%Y')

    def __unicode__(self):
        if not hasattr(self, 'cert'):
            return "%s %s" % (
                self.user.username,
                self.date_created)
        else:
            return "%s %s * %s" % (
                self.user,
                self.date_created,
                self.cert.fingerprint_sha1)

    class Meta:
        verbose_name = "Public Key"
        verbose_name_plural = "Public Keys"
        db_table = "webid_provider_pubkey"


class ActiveCertManager(models.Manager):
    """
    default manager for Certs. returns only
    the Certs with PubKeys in which is_active = True
    """
    def get_query_set(self):
        return super(ActiveCertManager,
                self).get_query_set().filter(pubkey__is_active=True)


class Cert(models.Model):
    """
    Class for storing certificate info.
    """
    #XXX we can also store here info from visiting Users.
    #So we check certstr on auth.
    #created_by_us = False

    pubkey = models.OneToOneField(PubKey)

    valid_from = models.DateTimeField(blank=True)
    expires = models.DateTimeField(blank=True)

    #XXX property: days until expiration.
    #a task can be used to warn users about
    #upcoming expirations.

    #fingerprint is a property of PubKey or of Cert???
    fingerprint_sha256 = models.CharField(max_length=95)
    fingerprint_sha1 = models.CharField(max_length=60)
    fingerprint_md5 = models.CharField(max_length=50)

    #It can help the user to recognize
    #in which browser was installed...
    user_agent_string = models.CharField(max_length=255, null=True, blank=True)
    comment = models.CharField(max_length=255, null=True, blank=True)

    #algorithm??
    #Format (pkcs10, 12, 7...)

    objects = ActiveCertManager()
    all_objects = models.Manager()

    class Meta:
        verbose_name = "x509 Certificate"
        verbose_name_plural = "x509 Certificates"
        #app_label = "django_webid_provider"
        db_table = "webid_provider_cert"

    def __unicode__(self):
        return "%s's cert with Fingerprint %s" % (
                self.pubkey.user.username,
                self.fingerprint_sha1)


class WebIDURI(models.Model):
    """
    This class stores the URI for WebIDUsers.
    (The URI where we retrieved the WebIDProfile for
    external users; the URI that we have assigned
    thru a callback on hosted users.
    It can be accessed through WebIDUser proxy model.
    """
    uri = models.URLField(null=True, blank=True)
    user = models.ForeignKey(User, unique=True,
            related_name="stored_webiduris")
    #External/Internal (hosted) webid users.
    _is_user_hosted_here = models.BooleanField()
    #@property internal_user / external_user
    #We can still add some fields (here?)
    #related to the de-referenced uri
    #i.e., timestamp of profile fetching, content-type, ...
    #that can help to the periodical re-fetching.

    class Meta:
        #app_label = "django_webid_provider"
        db_table = "webid_provider_webiduri"


class WebIDUser(User):
    """
    Proxy model for accessing WebIDUsers.
    Implements methods for filtering own/external users, and
    retrieving the absolute WebID URI.
    """

    class Meta:
        proxy = True

    #XXX have to think about this.
    #but here we can
    # - add managers (to separate "hosted" users from external users)
    # - add properties (shortcuts to attr / methods on the profile)

    @staticmethod
    def get_for_user(user):
        return WebIDUser.objects.get(id=user.id)

    @staticmethod
    def get_for_uri(uri):
        try:
            return WebIDUser.objects.get(stored_webiduris__uri=uri)
        except WebIDUser.DoesNotExist:
            return None

    def _get_webid_url(self):
        #XXX FIXME
        #if it is hosted (see checking profile)
        #return reverse url
        #XXX in the future, we can use any other
        #user field. Use contenttypes in CertConfig.
        return reverse('webidprovider-webid_uri',
                kwargs={'username': self.username})

    webid_url = property(_get_webid_url)
    #XXX in the property, need to hook a configurable callback.
    #XXX should raise exception on _set,
    #or use proper fields.

    def _get_absolute_webid_uri(self):
        #XXX should do something about the HTTP(S)
        #for the future

        #Hmm what about putting https and then http?
        #Does the spec handle the recursion gracefully?
        #webid.auth module does not.

        #XXX document that we NEED TO HAVE SITES APP WORKING.
        #XXX get a setting for this?

        uri = "http://%s%s#me" % (
                Site.objects.get_current().domain,
                self._get_webid_url())
        return uri

    absolute_webid_uri = property(_get_absolute_webid_uri)

    @property
    def keys(self):
        #only active keys (keys have overriden manager)
        return self.pubkey_set.all()

    def _get_uri(self):
        """
        property that retrieves the webiduri object
        via FK.
        """
        #XXX we MUST hook here a possible callback to retrieve uris.
        uris = self.stored_webiduris.all()
        if uris.count() > 0:
            return uris[0]
    #XXX this is confusing with the webid_url and absoulte_webid_uri above!!!
    storeduri = property(_get_uri)

    def __unicode__(self):
        return self.username


class WebIDProfile(models.Model):
    """
    Abstract model for different WebID profiles.
    Optional Use (fallback)
    """
    #XXX we could try to use
    #zope.interface here... (so to enforce all child models
    #have a certain set of methods).
    #we can also define a stub for each method??.

    #we store here the webid_uri for external users.
    #for internal users you should use the absolute_webid_uri
    #property of WebIDUser

    #XXX Move this to WebIDUser ^^^
    #uri = models.URLField()
    user = models.OneToOneField(WebIDUser)

    #XXX move this to WebIDUser ^^^

    class Meta:
        abstract = True
        #app_label = "django_webid_provider"


class WebIDBasicProfile(WebIDProfile):
    """"
    Sample implementation of WebIDProfile
    """
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)

    class Meta:
        #app_label = "django_webid_provider"
        db_table = "webid_provider_webidbasicprofile"
