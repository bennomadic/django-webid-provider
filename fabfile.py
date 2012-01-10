from __future__ import with_statement
from fabric.api import *
from fabric.colors import green

# Local testing

def test():
    """
    Run tests for django_webid.provider
    """
    local("python ./run_tests.py")
    print("")
    print(green("[OK] Tests were passed ok!"))


def init():
    """
    Initialize a virtualenv in which to run tests against this
    """
    local("virtualenv .")
    #local("pip install -E . -r examples/example_webid_provider/requirements/libs.txt")
    local("pip install -E . -r examples/example_webid_provider/requirements/external_apps.txt")
    local("python setup.py sdist")
    local("pip install -E . dist/django_webid.provider-0.1.tar.gz")
    print(green("[OK] env has been initializated"))

def rebuild():
    """
    re-builds the package
    """
    local("rm -rf dist/")
    local("python setup.py sdist")
    local("pip install -E . -I -U dist/django_webid.provider-0.1.tar.gz")
    print(green("[OK] env has been rebuilt"))

def clean():
    """
    Remove the cruft created by virtualenv and pip
    """
    local("rm -rf bin/ include/ lib/ dist/")
    print(green("[OK] env has been cleaned"))



##############################################
# Deployment
##############################################

execfile('.PROD')

def deploy():
    code_dir = env.code_dir
    repo = env.repo
    with settings(warn_only=True):
        if run("test -d %s" % code_dir).failed:
            run("git clone %s %s" % (repo, code_dir))
    with cd(code_dir):
        run("git pull origin master")
        run("~/webid_scripts/webid_build.sh")
        run("~/webid_scripts/webid_reset_wsgi.sh")
    print("")
    print(green("[OK] Code has been deployed"))

def init_and_deploy():
    code_dir = env.code_dir
    repo = env.repo
    with settings(warn_only=True):
        if run("test -d %s" % code_dir).failed:
            run("git clone %s %s" % (repo, code_dir))
    with cd(code_dir):
        run("git pull origin master")
        run("~/webid_scripts/webid_init_and_build.sh")
        run("~/webid_scripts/webid_reset_wsgi.sh")
    print("")
    print(green("[OK] Code has been deployed"))

def reset_db():
    code_dir = env.code_dir
    with cd(code_dir):
        run("git pull origin master")
        run("~/webid_scripts/webid_reset_db.sh")
    print ""
    print(green("[OK] Database has been reset (with no mercy)"))

###############################################
# to check (copied from somewhere, not working
# with last versions)

def git_pull():
    "Updates the repository."
    run("cd ~/git/$(repo)/; git pull $(parent) $(branch)")

def git_reset():
    "Resets the repository to specified version."
    run("cd ~/git/$(repo)/; git reset --hard $(hash)")

def prod():
    env.fab_hosts = env.hosts
    #FAB_HOSTS is defined in .PROD file
    env.repos = (('django-webid-provider','origin','master'),)


###############################################


def reboot():
    "Reboot Apache2 server."
    sudo("apache2ctl graceful")

def pull():
    require('fab_hosts', provided_by=[prod])
    for repo, parent, branch in env.repos:
        env.repo = repo
        env.parent = parent
        env.branch = branch
        execute(git_pull)

def reset(repo, hash):
    """
    Reset all git repositories to specified hash.
    Usage:
        fab reset:repo=my_repo,hash=etcetc123
    """
    require("fab_hosts", provided_by=[prod])
    env.hash = hash

    env.repo = repo
    execute(git_reset)
