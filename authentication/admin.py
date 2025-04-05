from django.contrib import admin
from django.apps import apps

# Get all models from the current app
app_models = apps.get_app_config('authentication').get_models()

# Register all models dynamically
for model in app_models:
    try:
        admin.site.register(model)
    except admin.sites.AlreadyRegistered:
        pass  # Ignore already registered models
