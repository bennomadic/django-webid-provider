import sys, os

try:
    execfile('bin/activate_this.py',
                 dict(__file__='./bin/activate_this.py'))
except IOError:
    print("""ERROR: Looks like you do not have a virtualenv in the current dir.
       No virtualenv, no tests, sorry :(""")
    sys.exit(1)

from django.conf import settings
from django.conf.urls.defaults import patterns, include
from django.core.management import call_command

setup_root = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(setup_root, "src"))
sys.path.insert(0, os.path.join(setup_root, "examples"))



def main():
    # Dynamically configure the Django settings with the minimum necessary to
    # get Django running tests
    settings.configure(
        INSTALLED_APPS=(
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django.contrib.sites',
            'django.contrib.staticfiles',
            'uni_form',
            'django_webid.provider',
        ),
        # Django replaces this, but it still wants it. *shrugs*
        DATABASE_ENGINE='sqlite3',
        SITE_ID=1,
        AUTH_PROFILE_MODULE = 'django_webid.provider.WebIDBasicProfile',
        ROOT_URLCONF = 'example_webid_provider.urls',

    )

    # Fire off the tests
    call_command('test', 'provider')

if __name__ == '__main__':
    main()
