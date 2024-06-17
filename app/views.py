from django.shortcuts import redirect
from django.views.generic import TemplateView
from django.views.generic.edit import CreateView
from .models import IT_Personnel, School, microFocusAdmin
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate
from django.contrib.auth.views import LoginView
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.forms import PasswordInput
from django.utils import timezone


#Authentication Views
class ITPersonnelRegisterView(CreateView):
    """
    Create a new IT_Personnel instance and associate it with a new User instance.
    """
    model = IT_Personnel
    fields = ['first_name', 'last_name', 'email', 'school_name', 'password']
    template_name = 'it_personnel_register.html'
    #success_url = '/login/'


    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        form.fields['password'].widget = PasswordInput()
        return form

    def form_valid(self, form):
        # Create a new User instance
        user = User.objects.create_user(
            username=form.cleaned_data['email'],
            email=form.cleaned_data['email'],
            password=form.cleaned_data['password'],
            last_login=timezone.now()
        )

        # Create a new School instance if it doesn't already exist
        school_name = form.cleaned_data['school_name']
        school, created = School.objects.get_or_create(name=school_name)

        # Create a new IT_Personnel instance and associate it with the new User and School
        it_personnel = form.save(commit=False)
        it_personnel.user = user
        it_personnel.school = school  # Assign the school object directly
        it_personnel.save()
        return super().form_valid(form)

    
    
    

class userLoginView(LoginView):
    """
    Authenticate the IT_Personnel or Admin user based on the provided email and password.
    """
    model = User
    fields = ['username', 'password']
    template_name = 'login.html'
    form_class = AuthenticationForm

    def form_valid(self, form):
        """
        Overriding the form_valid method to authenticate the user.
        """
        username = form.cleaned_data['username']
        password = form.cleaned_data['password']
        user = authenticate(
            self.request, username=username, password=password
        )
        if user is not None:
            login(self.request, user)
            if hasattr(user, 'it_personnel'):
                # User is an IT_Personnel
                messages.success(self.request, "Login successful! Welcome, IT Personnel.")
                return redirect('it_personnel_dashboard')
            elif hasattr(user, 'microfocusadmin'):
                # User is a microFocusAdmin
                messages.success(self.request, "Login successful! Welcome, Admin.")
                return redirect('admin_dashboard')
        else:
            return self.form_invalid(form)


class ITPersonnelDashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'it_personnel_dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add any necessary data for the IT personnel dashboard
        return context


class AdminDashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'admin_dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add any necessary data for the admin dashboard
        return context
   
    


def passwordResetView():
    """
    Implement a password reset flow,
    which may involve sending a reset token to the user's email and updating the User password.
    """
    pass 

#School IT Personnel Views
def accessKeyListView():
    """
    Fetch all Access_Key instances associated with the IT_Personnel's school_id and display them.
    """
    pass

def accessKeyDetailView():
    """
    Fetch a specific Access_Key instance and display its details.
    """
    pass


def accessKeyPurchaseView():
    """
    Create a new Access_Key instance associated with the
    IT_Personnel's school_id, but only if there is no active key already assigned to that school_id.
    """
    pass

# Micro-Focus Admin Pages
def accessKeyListView():
    """
    Fetch all Access_Key instances and display them
    """
    pass

def accessKeyRevokeView():
    """
    Update the status of a specific Access_Key instance to "Revoked".
    """
    pass
