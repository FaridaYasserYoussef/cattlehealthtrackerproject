from django.contrib import admin
from django.apps import apps
from .models import UserApp
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin



class CustomUserAdmin(BaseUserAdmin):
    model = UserApp
    fieldsets = BaseUserAdmin.fieldsets + (
    (None, {'fields': (
        "mobile_number","two_fa_enabled", "farm", "role", "created_at", "updated_at"
    )}),
    )
admin.site.register(UserApp, CustomUserAdmin)
# Get all models from the current app
app_models = apps.get_app_config('authentication').get_models()

# Register all models dynamically
for model in app_models:
    if model == UserApp:
        continue
    try:
        admin.site.register(model)
    except admin.sites.AlreadyRegistered:
        pass  # Ignore already registered models
