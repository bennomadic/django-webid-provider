import base64
import logging
import re
from datetime import datetime

from OpenSSL import crypto
import M2Crypto as m2crypto

#XXX GOD KILLS A KITTEN EVERY TIME
#WE USE BOTH WRAPPERS TOGETHER!!!
#Hopefully, Santa bring us an improved m2crypto API
#since we've been good people...


class CertificateCreationError(Exception):
    pass


class CertOptions(object):
    pass


class CertCreator(object):
    """
    The magic class that hides
    all the x509 operations,
    _and_ saves PubKey and Cert
    instances to the database.
    """

    def __init__(self, spkac_str, user, **kwargs):
        """
        Receive spkac_str and create cert.
        On the **kwargs dict we can receive custom
        parameters for the cert creation (from advanced views).
        """
        #XXX FIXME get spkac_str as a kw arg.
        self.user_agent_string = kwargs.get('user_agent_string', None)
        self.skip_sign = kwargs.get('skip_sign', False)

        self._get_cert_configs(**kwargs)
        self._get_user_data(user)
        self._get_csr(spkac_str)
        self._verify_csr()
        self._init_cert()

    #####################################################
    # Private Methods
    # (mostly sequential CRYPTO FUNCTIONS)
    #####################################################

    def _get_cert_configs(self, **kwargs):
        from django_webid.provider.models import CertConfig
        certconfig = CertConfig.objects.single()

        #get datadicts from certconfig
        default_subject_data = certconfig.get_subject_data()
        default_cn_field = certconfig.get_common_name_field()
        default_validity_data = certconfig.get_validity()

        opt = CertOptions()
        opt.subject_data = default_subject_data
        opt.cn_field = default_cn_field
        opt.validity_data = default_validity_data

        #Now we override with **kwargs fields
        #coming from advanced options view form.
        #XXX get OVERRIDES values from the defaults settings!
        overrides = {}
        POSSIBLE_OVERRIDES = (
                "from_days",
                "for_days",
                "valid_from_ts",
                "expires_ts",
                )
        for k in POSSIBLE_OVERRIDES:
            if kwargs.has_key(k):
                overrides[k] = kwargs[k]

        #validity overrides
        for k in opt.validity_data.keys():
            if k in overrides.keys():
                opt.validity_data[k] = overrides[k]

        for k in ('valid_from_ts', 'expires_ts'):
            if k in overrides.keys():
                opt.validity_data[k] = overrides[k]

        #XXX TODO: FINISH OVERRIDES
        #XXX TODO: we can flatten the options
        #with a small namespace: val_data_foobar
        #might split...

        #issuerKey override (for test purposes mainly)
        issuerKey = kwargs.get('issuerKey',None)
        if issuerKey:
            self.issuerKey = issuerKey

        self.opts = opt


    def _get_user_data(self, user):
        from django_webid.provider.models import WebIDUser
        u = WebIDUser.get_for_user(user)
        webid = u.absolute_webid_uri

        #XXX check for errors
        self.URI_STR = 'URI:%s' % (webid)
        #to be used in subjectAltName
        self.webiduser = u

    def _get_csr(self, spkac_str):
        """
        gets a NetscapeSPKI object from the spkac_str
        or loads a PKCS10
        """
        # TODO should figure out how to use this
        # challenge thing (spkac is using md5, so
        # I guess there should be some time bound)
        # maybe linked to session or something???
        # See https://www.w3.org/Bugs/Public/show_bug.cgi?id=13518
        #http://www.w3.org/wiki/Foaf%2Bssl/Clients#Keygen
        # We could der-decode the spkac and get the challenge from there.

        spkac_str = re.sub('\s', '', spkac_str)
        #print('SPKAC PUBKEY=%s' % spkac_str)
        logging.debug('SPKAC PUBKEY=%s' % spkac_str)

        if "BEGINIECERTIFICATEREQUEST" in spkac_str:
            #XXX improve csr type detection (get a flag from view)
            pkcs10 = spkac_str.replace(
                    '-----BEGINIECERTIFICATEREQUEST-----','').replace(
                    '-----ENDIECERTIFICATEREQUEST-----','')

            der = base64.b64decode(pkcs10)
            self.csr = crypto.load_certificate_request(
                    crypto.FILETYPE_ASN1, der)
            self.csr_type = "msie"

        else:
            self.csr = crypto.NetscapeSPKI(spkac_str)
            self.csr_type = "spki"

    def _verify_csr(self):
        pk = self.csr.get_pubkey()
        check = self.csr.verify(pk)
        if check != 1L:
            raise CertificateCreationError('Server could not verify the CSR')

    def _init_cert(self):
        """
        create an empty cert
        """
        self.cert = crypto.X509()


    # ***
    # begins crypto functions that alter the certificate

    def _create_key_pair(self, _type, bits):
        pkey = crypto.PKey()
        pkey.generate_key(_type, bits)
        return pkey

    def _set_cert_subject(self):
        for code, val in self.opts.subject_data.items():
            setattr(self.cert.get_subject(), code, val)
        #XXX in the UID we can also write the webid URI

    def _create_issuer(self):
        icert = crypto.X509()
        #XXX get this from CertConfig ?
        #XXX have it cached somewhere?
        issuer_data = (('CN', 'Not a Certification Authority'),
                        ('O', 'FOAF+SSL'),
                        ('OU', 'The Community of Self Signers'))
        for k,v in issuer_data:
            setattr(icert.get_subject(), k, v)
        self.icert = icert

    def _set_issuer(self):
        self._create_issuer()
        self.cert.set_issuer(self.icert.get_subject())

    def _set_common_name(self):
        cn_field = getattr(self.webiduser,
                self.opts.cn_field,
                None)
        if not cn_field:
            cn_field = gettattr(self.webiduser,
                    'username')
        self.cert.get_subject().CN = cn_field

    def _set_pubkey(self):
        """
        gets the pubkey from the certificate request
        and adds it to the x509 cert.
        """
        pk = self.csr.get_pubkey()
        self.cert.set_pubkey(pk)

    def _set_fake_serial(self):
        """
        we replace this serial later,
        but seems we need a well-formed cert
        to be able to dump it... not needed
        after we get over the dirty workaround
        between M2 and PyOpenSSL...
        """
        self.cert.set_serial_number(0)

    def _set_validity(self):
        """
        sets validity parameters
        """
        val_data = self.opts.validity_data
        fmt = '%Y%m%d%H%M%SZ'
        #XXX Dont trust this data!
        #if not int, asssume 0 / 365

        nbts = val_data.get('valid_from_ts', None)
        if nbts and isinstance(nbts, datetime):
            self.cert.set_notBefore(nbts.strftime(fmt))

        else:
            not_before = 0 + (24 * 60 * 60 *
                    val_data['from_days'])
            self.cert.gmtime_adj_notBefore(not_before)

        nats = val_data.get('expires_ts', None)
        if nats and isinstance(nats, datetime):
            self.cert.set_notAfter(nats.strftime(fmt))
        else:
            #XXX We should allow also
            #advanced validity data in hours.
            valid_until = (24 * 60 * 60 *
                    val_data['for_days'])
            self.cert.gmtime_adj_notAfter(valid_until)

        # get the final cert validity data for
        # saving it in the db
        vdata = {}
        cnb = self.cert.get_notBefore()
        cna = self.cert.get_notAfter()
        vdata['notBefore'] = datetime.strptime(cnb, fmt)
        vdata['notAfter'] = datetime.strptime(cna, fmt)
        self.vdata_cert = vdata

    def _set_subject_alt_name(self):
        """
        here comes the magic for WebID!
        """
        ext = crypto.X509Extension('subjectAltName',
                1,
                self.URI_STR)
        self.cert.add_extensions([ext])

    def _set_version(self):
        # version 3 (decimal)
        self.cert.set_version(2)

    def _sign(self, issuerKey, digest="sha1"):
        self.cert.sign(issuerKey, digest)

    def _get_openssl_mod_exp(self):
        import binascii
        #@self.cert is an instance of OpenSSL.crypto.X509
        #dirty workaround with M2Crypto
        #FIXME!!!
        dump = crypto.dump_certificate(crypto.FILETYPE_PEM,
                self.cert)
        m2c = m2crypto.X509.load_cert_string(dump)
        pubkey = m2c.get_pubkey()
        mod = pubkey.get_modulus().lower()

        pkrsa = pubkey.get_rsa()
        e  = m2crypto.m2.rsa_get_e(pkrsa.rsa)
        ha = binascii.hexlify(e)
        #not correct
        #but it's not likely >3
        nbytes = ha.lstrip('0')[0]
        exp = int(ha[-int(nbytes)*2:],16)
        bits = pubkey.size() * 8

        return (mod, exp, bits)


    ##############################
    # done with crypto functions
    # Now: writing model instances
    ##############################

    #XXX can we decouple the instance writting
    #from the crypto functions??
    #--- As two separate classes...

    def _set_cert_serial_number(self, serial):
        self.cert.set_serial_number(serial)

    def _save_pubkey_instance(self):
        from django_webid.provider.models import PubKey

        mod, exp, bits = self._get_openssl_mod_exp()

        now = datetime.now()
        pk_instance = PubKey.objects.create(mod=mod,
                exp=exp,
                bits=bits,
                created=now,
                user=self.webiduser)

        #XXX TODO get Public Key Algorithm
        #from cert
        #and write into db

        #XXX could change this. We can have a table only
        #for serial counter, this not accurate.
        #But using the id of PubKey instances
        #is a good enough approximation.
        self._set_cert_serial_number(pk_instance.id)
        self.pk_instance = pk_instance

    def _set_cert_dump(self):
        if self.csr_type == "msie":
            filetype = crypto.FILETYPE_PEM
        else:
            filetype = crypto.FILETYPE_ASN1
        self.cert_dump = crypto.dump_certificate(
            filetype,
            self.cert)


    def _get_cert_hashes(self):
        """
        returns sha1 and md5 hashes of the
        certificate dump, as colon-delimited
        strings.
        """
        import hashlib
        beautify = lambda s: ':'.join([s[i:i+2] \
                for i in xrange(0, len(s), 2)])
        return (beautify(
                    hashlib.sha1(self.cert_dump).\
                            hexdigest()),
                beautify(
                    hashlib.md5(self.cert_dump).\
                            hexdigest()),
                beautify(
                    hashlib.sha256(self.cert_dump).\
                            hexdigest()))

    def _save_cert_instance(self):
        from django_webid.provider.models import Cert
        c = Cert()
        c.fingerprint_sha1, \
        c.fingerprint_md5,\
        c.fingerprint_sha256 = self._get_cert_hashes()
        self.fingerprint_md5 = c.fingerprint_md5
        self.fingerprint_sha1 = c.fingerprint_sha1
        self.fingerprint_sha256 = c.fingerprint_sha256

        c.pubkey = self.pk_instance

        c.valid_from = self.vdata_cert['notBefore']
        c.expires = self.vdata_cert['notAfter']

        c.user_agent_string = self.user_agent_string
        c.save()


    #####################################################
    #####################################################
    # Public Methods
    #####################################################
    #####################################################

    def create_cert(self):
        """
        sequential calls to all methods
        that, in that order, lead to a valid
        certificate creation
        """
        ######################
        #CERT CREATION PROCESS
        ######################
        self._set_cert_subject()
        self._set_common_name()
        self._set_pubkey()
        self._set_fake_serial()
        self._set_validity()
        self._set_issuer()
        self._set_subject_alt_name()
        self._set_version()

        #XXX can we cache this? better to create it every time???
        #it will add overhead to every request! :(
        #but where do we store the pkey safely?
        #The funny thing is that we only need the signature
        #so the browser's cert store does not crash...

        if not self.skip_sign:
            if not hasattr(self, 'issuerKey'):
                issuerKey = self._create_key_pair(
                        crypto.TYPE_RSA, 1024)
            else:
                issuerKey = self.issuerKey
            self._sign(issuerKey)

        #saving instances
        #XXX transaction block?
        self._save_pubkey_instance()
        self._set_cert_dump()
        self._save_cert_instance()

    def get_cert_dump(self):
        """
        returns a string containing the
        dump of the certificate.
        """
        return self.cert_dump

    def get_b64_cert_dump(self):
        """
        returns a string containing the
        base64 representation of the certificate
        dump
        """
        return base64.b64encode(self.cert_dump)

    def get_sha1_fingerprint(self):
        return self.fingerprint_sha1



###############################################
###############################################
# SOME OTHER OLD FUNCTIONS FROM our legacy code
# (coming from xmppwebid)
###############################################
# To be cleaned and reused
# (pkcs12, i'm looking at you)

def get_serial_from_file(serial_path='/tmp/webid_cert_serial.txt'):
    """Get serial number from file

    :param serial_path: serial file path
    :type serial_path: string
    :return: serial number
    :rtype: int

    :TODO: XXX this serial number is a quick hack.
    this should be tracked in a model table. XXX

    """
    try:
        serial_file = open(serial_path, "r")
        data = serial_file.read()
        serial_file.close()
        if data: number = int(data)
        number += 1
    except:
        number = 1
    serial_file = open(serial_path, "w")
    serial_file.write(str(number))
    serial_file.close()
    return number

def gen_keypair(bits=1024):
    """Create RSA key pair
    Equivalent to: openssl genrsa -des3 -out client.key 1024

    :param bits: key bits length
    :type bits: int
    :return: key
    :rtype: EVP.PKey

    """
    pkey = EVP.PKey()
    rsa = RSA.gen_key(bits, 65537)
    pkey.assign_rsa(rsa)
    #print "Generated private RSA key"
    # Print the new key as a PEM-encoded (but unencrypted) string
    logging.debug(rsa.as_pem(cipher=None))
    return pkey


def gen_csr(pkey):
    """Create an x509 CSR (Certificate Signing Request)
    Equivalent to: openssl req -new -key client.key -out client.csr

    :param pkey: key
    :type pkey: EVP.PKey
    :return: x509 request
    :rtype: X509.Request

    """

    csr = X509.Request()
    csr.set_pubkey(pkey)
    return csr


def gen_cert_from_csr(csr, serial_number=0, years=1):
    """Create an x509 certificate from CSR with default values

    :param csr: x509 certificate request
    :type csr: X509.Request
    :param serial_number: certificate serial number
    :type serial_number: string
    :param years: number of years the certificate is going to be valid
    :type years: int
    :return: x509 certificate
    :rtype: X509.X509

    """
    cert = X509.X509()
    pkey = csr.get_pubkey()
    cert.set_pubkey(pkey)
    # the cert subject is the same as csr subject
    # get subject from request
    x509_name = csr.get_subject()
    cert.set_subject(x509_name) # the same if a csr subject was created
    # set version
    #:TODO: check that changing jabberd version here can remain 3
    cert.set_version(2)
    #:TODO: set a real serial number
    set_serial(cert, serial_number)
    set_valtime(cert, years)
    return cert

def set_cert_httpwebid(cert, webid):
    #XXX REFACTOR with above!!!

    """Set the SubjectAltName, Issuer and Subject

    :param cert: x509 certificate
    :type cert: X509.X509
    :param webid: FOAF WebId
    :type webid: string
    :return: x509 certificate
    :rtype: X509.X509

    """
    # optional
    # the issuer is going to be the same as subject
    x509_name = X509.X509_Name()
    x509_name.O = O
    x509_name.OU = OU
    x509_name.CN = CN
    cert.set_issuer(x509_name)

    # set subjectAltName extension
    ext = X509.new_extension('subjectAltName',
          'URI:%s' %(webid))
    ext.set_critical(1)
    cert.add_ext(ext)
    return cert

def sign_cert(pkey, cert):
    """Sign the cert

    :param pkey: key
    :type pkey: EVP.PKey
    :param cert:  x509 certificate
    :type cert: X509.X509
    :return: x509 certificate, key
    :rtype: X509.X509, EVP.PKey

    """
    cert.sign(pkey, 'sha1')
    return cert, pkey


def gen_httpwebid_selfsigned_cert(webid, serial_number=0, years=1, nick=None):
    """Create an x509 self-signed certificate

    Equivalent to: openssl x509 -req -days 365 -in client.csr
    -signkey client.key -out client.crt

    :param webid: FOAF WebId
    :type webid: string
    :param serial_number: certificate serial number
    :type serial_number: string
    :param years: number of years the certificate is going to be valid
    :type years: int
    :return: x509 self-signed certificate, key
    :rtype: tuple (X509.X509, EVP.PKey)

    """

    pkey = gen_keypair()
    csr = gen_csr(pkey)

    #XXX this changes (refactor)
    csr = set_csr_httpwebid(csr, webid, nick=nick)
    csr, pkey = sign_csr(pkey, csr)
    #XXX

    cert = gen_cert_from_csr(csr, serial_number, years)
    cert = set_cert_httpwebid(cert, webid)
    cert, pkey = sign_cert(pkey, cert)

    # Print the new certificate as a PEM-encoded string
    #print "Generated new self-signed client certificate"
    logging.debug(cert.as_pem())

    return cert, pkey



def gen_httpwebid_selfsigned_cert_pemfile(webid,
        cert_path='/tmp/webid_cert.pem',
        key_path='/tmp/webid_key.key',
        serial_path='/tmp/webid_cert_serial.txt', years=1, nick=None):
    """Create an x509 self-signed certificate and save it as PEM file

    :param serial_path: serial file path
    :type serial_path: string
    :param webid: FOAF WebId
    :type webid: string
    :param years: number of years the certificate is going to be valid
    :type years: int
    :param cert_path: certificate path
    :param key_path: key path
    :type cert_path: string
    :type key_path: string
    :return: x509 certificate path, key path
    :rtype: tuple (string, string)

    """
    #XXX get serial from db!!!
    serial_number = get_serial_from_file(serial_path)
    cert, pkey = gen_httpwebid_selfsigned_cert(webid,
            serial_number=serial_number,
            years=years, nick=nick)
    save_pkey_cert_to_pemfile(cert, pkey, cert_path, key_path)
    return cert_path, key_path



##########################################
# PKCS12 SHIT
# ANOTHER SPOT WHERE WE NEED PYOPENSSL !!!
# OR A PROPER PKCS12 WRAPPER!!!
# (I keep thinking that pkcs12 as a fallback
# is a good thing... f.i., for some mobile
# users...
##########################################

def save_pkcs12cert_to_pkcs12file(p12, p12cert_path='/tmp/webid_cert.p12'):
    """Save PKCS12 certificate to file

    :param p12: PKCS12 certificate
    :type p12: OpenSSL.crypto.PKCS12
    :param p12cert_path: PKCS12 certificate path
    :type p12cert_path: string
    :return: PKCS12 certificate path
    :rtype: string

    """
    p12cert = open(p12cert_path,"w")
    p12cert.write(p12.export())
    p12cert.close()
    return p12cert_path


def pemfile_2_pkcs12file(cert_path='/tmp/webid_cert.pem',
        key_path='/tmp/webid_key.key',
        p12cert_path='/tmp/webid_cert.p12'):
    """Create a PKCS12 certificate and save it from x509 certificate and
    key files as PEM

    :param cert_path: certificate path
    :param key_path: key path
    :param p12cert_path: key path
    :type cert_path: string
    :type key_path: string
    :type p12cert_path: string
    :return: PKCS12 certificate path
    :rtype: string

    """
# need the OpenSSL type
#    pkey = get_pkey_from_pkeypemfile(key_path)
#    cert = get_cert_from_certpemfile(cert_path)
    pkey = crypto.load_privatekey(OpenSSL.SSL.FILETYPE_PEM,
                                          open(key_path).read())
    cert = crypto.load_certificate(OpenSSL.SSL.FILETYPE_PEM,
                                           open(cert_path).read())
    p12 = pkey_cert_2_pkcs12cert(cert, pkey)
    p12cert_path = save_pkcs12cert_to_pkcs12file(p12, p12cert_path)
    return p12cert_path

