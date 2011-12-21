.. _ref-introduction:

===========================
About django-webid-provider
===========================

django-webid-provider is a pluggable django app that allows the creation and management
of `WebID`_ profiles, to be used in the `WebID`_ authentication protocol.

It enables a webID URI per user, and allows the user to install the x509 Certificates that
point to her webID profile.

Coming soon:
- django-webid-auth:  a Django middleware to provide WebID autentication



Technologies
============

* WebID for authentication
* `FOAF`_ ontology for the user WebID profile
* `Certificate`_ and `RSA`_ vocabularies to associate the user certificate public key to the WebID
* `X509`_ certificates
* `TLS`_ protocol for secure communications


Install
========
See :ref:`ref-install`

Documentation
=============

- This documentation: ref:`ref-introduction`

Download
=========
You can download this project in either
 * `zip`_ or
 * `tar`_ formats.
 
You can also clone the project with `Git`_ by running::
    $ git clone git://github.com/bennomadic/django-webid-profile

Bugs and features
=================
...

License
=======
django-webid-provider is copyright 2011 by [...] and is covered by the `GPLv3`_

Contact
========
(bennomadic at gmail dot com)

Acknowledgments
================
`foaf-protocols`_ community 




.. _WebID: http://www.w3.org/2005/Incubator/webid/spec/
.. _SPARQL: http://www.w3.org/TR/rdf-sparql-query/
.. _FOAF: http://xmlns.com/foaf/spec/
.. _Django: http://djangoproject.com/
.. _zip: http://github.com/xmppwebid/xmppwebid/zipball/master
.. _tar: http://github.com/xmppwebid/xmppwebid/tarball/master
.. _Git: http://git-scm.com
.. _GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
.. _In-Band-Registration: http://xmpp.org/extensions/xep-0077.html
.. _TLS: http://tools.ietf.org/html/rfc5246
.. _Certificate: http://www.w3.org/ns/auth/cert
.. _RSA:  http://www.w3.org/ns/auth/rs
.. _X509: http://www.itu.int/rec/T-REC-X.509/en
.. _foaf-protocols: http://lists.foaf-project.org/mailman/listinfo/foaf-protocols
