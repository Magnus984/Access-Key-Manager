from django.test import TestCase, Client
from django.urls import reverse
from .models import IT_Personnel, microFocusAdmin, School
from django.contrib.auth.models import User

# Create your tests here.
class ITPersonnelRegisterViewTestCase(TestCase):
    def test_register_with_existing_email(self):
    # Create a user with the same email as the one we're trying to register
        User.objects.create_user(username='existing_user', email='jodin999@gmail.com')

        # Submit the form with the existing email
        response = self.client.post(reverse('register'), {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'jodin999@gmail.com',
            'school_email': 'test@example.com',
            'school_name': 'Test School',
            'password': 'TestPassword123!',
        })
        #self.assertFormError(form, 'email', 'I t_ personnel with this Email already exists.')
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))


    def test_register_with_weak_password(self):
    # Submit the form with a weak password
        response = self.client.post(reverse('register'), {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'existing_email@example.com',
            'school_email': 'test@example.com',
            'school_name': 'Test School',
            'password': 'short',
        })

        # Check that the form has an error on the 'password' field
        form = response.context['form']
        self.assertFormError(form, 'password', 'This password is too short. It must contain at least 8 characters.')


class UserLoginViewTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.school = School.objects.create(name='Test School')
        self.it_personnel = User.objects.create_user(
            username='it_personnel@example.com', email='it_personnel@example.com', password='testpassword'
        )
        self.it_personnel.it_personnel = IT_Personnel.objects.create(user=self.it_personnel, school=self.school)
        self.admin = User.objects.create_user(
            username='admin@example.com', email='admin@example.com', password='testpassword1'
        )
        self.admin.microfocusadmin = microFocusAdmin.objects.create(user=self.admin)

    def test_login_it_personnel(self):
        """
        Test that an IT_Personnel user can log in successfully.
        """
        response = self.client.post(reverse('login'), {
            'username': 'it_personnel@example.com',
            'password': 'testpassword'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('it_personnel_dashboard'))
    def test_login_admin(self):
        """
        Test that a microFocusAdmin user can log in successfully.
        """
        response = self.client.post(reverse('login'), {
            'username': 'admin@example.com',
            'password': 'testpassword1'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('admin_dashboard'))