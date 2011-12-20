import os
PROJECT_ROOT = '/srv/www/django/foafgen/djangowebid-provider'

# the following settings are used for quick access to "site" info
SITE_ID = 1
SITE_NAME = 'foafgen'
HTTP_HOST = 'foafgen.net'
SITE_HOSTNAME = HTTP_HOST

ROOT_URLCONF = 'example_webid_provider.urls'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3', # Add 'postgresql_psycopg2', 'postgresql'    , 'mysql', 'sqlite3' or 'oracle'.
        'NAME': '/srv/www/django/foafgen/db/test.db',                      # Or path to database file if using sqlit    e3.
        'USER': '',                      # Not used with sqlite3.
        'PASSWORD': '',                  # Not used with sqlite3.
        'HOST': '',                      # Set to empty string for localhost. Not     used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not us    ed with sqlite3.
    }
}

