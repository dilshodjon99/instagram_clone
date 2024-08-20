from django.contrib import admin
from .models import User, UserConfirmation


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'first_name', 'last_name')
    list_display_links = ('username', 'first_name', 'last_name')


@admin.register(UserConfirmation)
class UserConfirmationAdmin(admin.ModelAdmin):
    list_display = ('user', 'code')
    list_display_links = ('user', 'code')
