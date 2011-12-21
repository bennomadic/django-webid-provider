import os
import sys
import site
# put the Django project on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../src/")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
os.environ["DJANGO_SETTINGS_MODULE"] = "example_webid_provider.settings"
os.environ["PYTHON_EGG_CACHE"] = "/tmp"
from django.core.handlers.wsgi import WSGIHandler
application = WSGIHandler()
