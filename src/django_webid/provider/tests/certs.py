import datetime
from OpenSSL import crypto

from django.utils import unittest
from django.contrib.auth.models import User

from django_webid.provider.certs.utils import CertCreator
from django_webid.provider.models import Cert

TEST_ICEWEASEL_SPKAC="MIICaDCCAVAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbPAp1rVLNOXTK3Lie0+0pKiJSOvMhvtSm2WBZQ4wvqtjpm1Ru45LR1d3Cq2JvJgSW2Ou9DqeKduhk8vwaxyALCV5wpKyVkJy6nA1e8IBL+NCg51pN4pIHW3O+0GRoMqgEnJn42JLocmDnUort4gHQZX8Ti9qYp11+LaIkhriWD9lDOq3hRgPAopdYEt5PbNkA//1d5EyhPnGac3MLirUbzCjLeOtaI1FT0+b29SwphbaaO1u7DHeJY52/duJr2/N9dJKdu+zDemvCgnz0QvmJRepbBDhjb0YprNeSLykNjVxZgQGBcxY8RZrNGajtwYQKZWb9LfLQVKIM1Tw3qBlJAgMBAAEWKGMxM2MxYjQ2ZjY5YjE0OWNlZDAxMmEyZDA4MzQxODg1MTMyODYwODQwDQYJKoZIhvcNAQEEBQADggEBAEvjEFNzPW9dpKzDhInyKPO1XH0p9cS9L5EopuXe2ZysB8C975BTUyfnLRLlB9aMFie6LZ5xbcVRAYiXtar57IGAslUP65WQmvUwnzYCi48Z29P0QU7VGkncoI5JTy4pOGkFHOnQUw+1NR3FL9owS91up7QiZ1RIsSsfyEZvDIJ/1iKZC5V7pK/oDy8bYBissImyfpn5rAG6cUrwZW8d2axh62F1kUVnMyftGsQy6+pU3DFE/GDK2ZhjWdJlvA+I1oIz7/Tg7sU2PK2mY+b7KuO0NeGVy2rrDdveuR4Ys8yLCm3iQD0iS0y8sZX05ee1a60Tng/qJy9dnQeUAoYVAsg="

TEST_MSIE_PKCS10=''

TEST_ISSUER_PKEY = '-----BEGIN PRIVATE KEY-----\nMIICeQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBAMIScjmDtte3FSXy\nB54nlNij65OK/tgR5UIKHY311sVa+a3P1Tkh8r+kOPzbLcUewRXl5IB74l8t4NhA\n6t2aL1oLpDZpFvXkUsNEdhNbgJ5Wjz/gwAxJ3Hyx0MwJZzbWrt0sjJLSpL0ClZe1\ncQXOu41wfA4VZCd0s18weSziyGHbAgMBAAECgYEAu6n0tHMOgsfydk/1V9T0lQzl\nhzXYOv4LD/ISJC0+cncHizC3Adk3EGPwC2qydrPHiLJWZHvnKZyGmPclZgZrk9ng\nYIZ/ZpT1/DTyUk3LeF+rgsOIkDIgNSijuH9kXNXN8r92eiqXkwHk4LMPZ3wV0OxV\nEO+SISj8ps5GgQuVvwECQQDw3AaPyeqNwaaiIEWzFe35PQnM2OwaCVjE27XDNxMl\n9GxLmLaCUMb17+glLjrbAN2ENhlTjYmaC+n81vd5HwNbAkEAzkWBSYRAuk5Cn2BF\n3flvSVJYyiWeejEUWooXGQjDxy1VEZFlv3hIVnNh8ob2YzyJB4ELwH0mMX9oATPL\nK+rjgQJBAMo4AK5SWUIg9vUhYUNlQwJBs+uvqDKH7GaDDIzUvZfdKdsiYQDyLskn\nXeFxeeqLRHAPN55Fs+SI4i/sj6O6XQcCQQCWM1KDoAQqJdapi0cU7g81SvtQp7gQ\nrjBuBWPwXMuC++WYF1IJ7KJwITDPk6tSc8AscLGIBxmKrYWkanyljDMBAkEAgc/t\ny6BXB9+2q37HfioRe7dV8/UlifNSli3JOU38UKiBuXaZ43cGzDkPqJM01B0FSosO\nUdqV9yLYuit5BUAKEQ==\n-----END PRIVATE KEY-----\n'

class WebIDCertsTestCase(unittest.TestCase):
    #urls = 'django_webid.provider.urls'
    def setUp(self):
        self.user = User.objects.create_user("test",
                'test@example.com', 'testpw')

    def tearDown(self):
        self.user.delete()

    def test_create_from_spkac(self):
        "Check creation and properties of a cert from a Netscape SPKAC"
        kwargs = {}
        kwargs['valid_from_ts'] = datetime.datetime(2012,1,1,12,0,0)
        kwargs['expires_ts'] = datetime.datetime(2012,12,31,12,0)

        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM,
            TEST_ISSUER_PKEY)
        kwargs['issuerKey'] = pkey

        cc = CertCreator(TEST_ICEWEASEL_SPKAC, self.user, **kwargs)
        cc.create_cert()
        cert = cc.cert

        s = cert.get_subject()
        self.assertTrue(isinstance(cert, crypto.X509))
        self.assertEqual(cert.get_serial_number(), 1L)

        #XXX this should take into account the CertOptions settings.
        self.assertEqual(s.get_components(),
            [('C', 'CC'), ('OU', 'The Community of Self Signers'),
            ('L', '/dev/null'), ('O', 'FOAF+SSL'), ('ST', 'Cyberspace'), ('CN',
                'test')])
        extension = cert.get_extension(0)
        self.assertEqual(extension.get_critical(), 1L)
        #XXX this should also get the WebIDUser
        #method for getting the absolute URI
        #IT Needs the defaultsite app for working.
        self.assertEqual(extension.get_data(),  '0"\x86 http://foafgen.net/webid/test#me')
        self.assertEqual(cert.get_notBefore(), '20120101120000Z')
        self.assertEqual(cert.get_notAfter(), '20121231120000Z')

        db_cert = Cert.objects.get(id=1)
        self.assertEqual(db_cert.fingerprint_sha1,
                'b0:db:47:c4:a8:98:cd:23:9e:a7:50:4b:95:25:a9:11:7f:d1:09:a9')
        self.assertEqual(db_cert.fingerprint_md5,
                'ea:fb:ed:0c:86:3f:ae:aa:4c:c7:c8:ba:7f:3d:ef:e4')
        #print crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

        #Check associated PubKey
        db_pkey = db_cert.pubkey
        self.assertEqual(db_pkey.mod, '9b3c0a75ad52cd3974cadcb89ed3ed292a22523af321bed4a6d96059438c2faad8e99b546ee392d1d5ddc2ab626f260496d8ebbd0ea78a76e864f2fc1ac7200b095e70a4ac95909cba9c0d5ef0804bf8d0a0e75a4de292075b73bed0646832a8049c99f8d892e87260e7528aede201d0657f138bda98a75d7e2da22486b8960fd9433aade14603c0a2975812de4f6cd900fffd5de44ca13e719a73730b8ab51bcc28cb78eb5a235153d3e6f6f52c2985b69a3b5bbb0c7789639dbf76e26bdbf37d74929dbbecc37a6bc2827cf442f98945ea5b0438636f4629acd7922f290d8d5c5981018173163c459acd19a8edc1840a6566fd2df2d054a20cd53c37a81949')
        self.assertEqual(db_pkey.exp, 65537)
        self.assertEqual(db_pkey.bits, 2048)
        self.assertEqual(db_pkey.is_active, True)
        self.assertEqual(db_pkey.user, self.user)


    def test_create_cert_from_pkcs10(self):
        "Check creation and properties of a cert from a MSIE PKCS10"
        #TODO
        pass

    #XXX###########################################
    #TODO
    #Check that config has a SITE entry (not example.org)
    #XXX related to the management command that populates the sites table.
    #XXX give a BAD spkac to see it fail :)
