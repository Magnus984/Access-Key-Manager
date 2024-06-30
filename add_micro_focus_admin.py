import os
import django
from django.utils import timezone

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Access_key_Manager.settings')
django.setup()

from django.contrib.auth.models import User
from app.models import microFocusAdmin

def create_micro_focus_admin(raw_password, first_name, last_name, email):
    # Create a new User instance
    user = User.objects.create_user(username=email, email=email, password=raw_password, last_login=timezone.now())

    # Create a new microFocusAdmin instance linked to the User
    admin_instance = microFocusAdmin.objects.create(
        user=user,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=user.password  # Use the hashed password from the User instance
    )

    # Save the instance to the database
    admin_instance.save()
    print("New microFocusAdmin instance created successfully")

if __name__ == "__main__":
    # Example usage
    create_micro_focus_admin(
        raw_password='admin_password',
        first_name='admin_firstname',
        last_name='admin_lastname',
        email='admin@example.com'
    )
