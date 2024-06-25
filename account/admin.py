from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import *


class UserModelAdmin(BaseUserAdmin):
    list_display = ('email', 'first_name', 'role', 'phone')
    list_filter = ('is_admin',)
    fieldsets = (
        ('User Credentials', {'fields': ('email', 'tfn', 'token')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'token'),
        }),
    )
    readonly_fields = ('created_at', 'tfn')
    search_fields = ('tfn', 'email', 'first_name')
    ordering = ('email', 'id')
    filter_horizontal = ()

admin.site.register(User, UserModelAdmin)

