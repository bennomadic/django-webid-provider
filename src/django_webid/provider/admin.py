from django.contrib import admin
from .models import CertConfig, PubKey, Cert, WebIDUser

class CertConfigAdmin(admin.ModelAdmin):
    """
    Admin class for the CertConfig model.
    """
    #XXX Add a Site behavior section.
    fieldsets = (
            ('App Behavior', {
                'fields': (
                    'hide_keygen_form',)}),
            ('Default Cert Subject', {
                'fields': (
                    'country_name',
                    'state',
                    'locality',
                    'organization',
                    'organizational_unit',
                    'common_name_field')}),
            ('Validity', {
                'classes': ('collapse',),
                'fields': (
                    'valid_for_days',
                    'valid_from_days')}),
                )

    def has_add_permission(self, request):
        """
        CertConfig behaves as a singleton.
        We populate it from the config when first syncing.
        """
        return False

    def has_delete_permission(self, request, obj=None):
        """
        CertConfig behaves as a singleton.
        We populate it from the config when first syncing.
        """
        #XXX FIXME should remove also the delete-action!!!
        return False

class CertAdmin(admin.ModelAdmin):
    """
    Admin class for Cert model.
    """
    readonly_fields = ( 'user_agent_string',
                        'fingerprint_sha256',
                        'fingerprint_sha1',
                        'fingerprint_md5')

class PubKeyAdmin(admin.ModelAdmin):
    """
    Admin class for PubKey model.
    """
    readonly_fields = ( 'mod',
                        'exp',
                        'bits',
                        'pkey_algorithm')

    #XXX FIXME get a better display
    #for the mod. beautify for the admin display??

admin.site.register(CertConfig, CertConfigAdmin)

#FIXME XXX Pubkey/Cert should be using Inlines.
admin.site.register(PubKey, PubKeyAdmin)
admin.site.register(Cert, CertAdmin)

#FIXME XXX WebIDUser could also use inlines to pubkeys.
admin.site.register(WebIDUser)
