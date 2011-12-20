#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup, find_packages
except ImportError:
    import ez_setup
    ez_setup.use_setuptools()
    from setuptools import setup, find_packages
import os

VERSION = __import__('django_webid.provider').__version__

def read(*path):
    return open(os.path.join(os.path.abspath(os.path.dirname(__file__)), *path)).read()

setup(
    #XXX ???
    name='django_webid.provider',
    namespace_packages = ['django_webid'],
    version=VERSION,
    description='Django app  intended to generate valid certificates for HTPP and XMPP WebID authentication',
    long_description=read('docs', 'intro.txt'),
    author='Ben Carrillo',
    author_email='bennomadic at gmail dot com',
    #
    download_url='https://github.com/bennomadic/django-webid-provider.git',
    #url=...
    packages=find_packages(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GPL License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: JavaScript',
        'Framework :: Django',
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='foaf, ssl, webid, x509, certificate, client certificate, authentication, authorization,django',
    include_package_data=True,
    zip_safe=False,
    exclude_package_data={
        'requirements': ['%s/*.tar.gz' % VERSION],
    },

)

