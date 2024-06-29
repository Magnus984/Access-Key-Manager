from django.shortcuts import redirect, render
from django.views.generic import TemplateView
from django.views.generic.edit import CreateView
from .models import IT_Personnel, School, microFocusAdmin, SchoolAccessKey, Access_Key
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate
from django.contrib.auth.views import LoginView, PasswordResetConfirmView
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.forms import PasswordInput
from django.utils import timezone
from django.urls import reverse_lazy, reverse
from django.core.mail import send_mail
from datetime import timedelta
import uuid
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django import forms
from django.http import JsonResponse
from django.views import View




def homepage(request):
    return render(request, 'index.html')


#Authentication Views
class ITPersonnelRegisterView(CreateView):
    """
    Create a new IT_Personnel instance and associate it with a new User instance.
    """
    model = IT_Personnel
    fields = ['first_name', 'last_name', 'email', 'school_email', 'school_name', 'password']
    template_name = 'it_personnel_register.html'
    success_url = '/login/'


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
        it_personnel.school = school
        it_personnel.set_password(form.cleaned_data['password'])
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

    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['reset_form'] = PasswordResetForm()
        return context


class ITPersonnelDashboardView(LoginRequiredMixin, TemplateView):
    """View for IT Personnel Dashboard"""
    template_name = 'it_personnel_dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        school_access_keys = SchoolAccessKey.objects.filter(
            school=self.request.user.it_personnel.school
        )
        context['access_keys'] = [sak.access_key for sak in school_access_keys]
        return context


class RevokeKeyForm(forms.Form):
    key_id = forms.IntegerField(label='Key ID')


class AdminDashboardView(LoginRequiredMixin, TemplateView):
    """View for Admin Dashboard"""
    template_name = 'admin_dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        access_keys = Access_Key.objects.all()
        context['access_keys'] = access_keys
        context['revoke_form'] = RevokeKeyForm()
        return context

    def post(self, request):
        """
        Update the status of a specific Access_Key instance to "Revoked".
        """
        revoke_form = RevokeKeyForm(request.POST)
        if revoke_form.is_valid():
            key_id = revoke_form.cleaned_data['key_id']
            try:
                access_key = Access_Key.objects.get(id=key_id)
                access_key.status = 'Revoked'  # Assuming there's a 'status' field
                access_key.save()

                # Remove association with schools
                SchoolAccessKey.objects.filter(access_key=access_key).delete()

                messages.success(request, 'Access key has been revoked.')
            except Access_Key.DoesNotExist:
                messages.error(request, 'Access key not found.')
        else:
            messages.error(request, 'Invalid form submission.')
        
        return redirect(reverse('admin_dashboard'))
   
    


def passwordResetView(request):
    """
    Implement a password reset flow,
    which may involve sending a reset token to the user's email.
    """
    if request.method == 'POST':
        reset_form = PasswordResetForm(request.POST)
        if reset_form.is_valid():
            email = reset_form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                reset_url = "{}://{}/password-confirm/{}/{}/".format(
                    request.scheme, request.get_host(), uid, token
                )
                
                context = {
                    'email': user.email,
                    'domain': request.get_host(),
                    'site_name': 'Your Site Name',
                    'uid': uid,
                    'user': user,
                    'token': token,
                    'protocol': request.scheme,
                    'reset_url': reset_url,
                }

                subject = render_to_string('password_reset_subject.txt', {}).strip()
                email_body = render_to_string('password_reset_email.txt', context)

                send_mail(
                    subject,
                    email_body,
                    'tettehmagnus35@gmail.com',  # from_email
                    [user.email],
                    fail_silently=False,
                )
                messages.success(request, "Password reset instructions have been sent to your email.")
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, "No user found with the provided email address.")
    else:
        reset_form = PasswordResetForm()

    return render(request, 'login.html', {'reset_form': reset_form, 'form': AuthenticationForm()})



class PasswordResetConfirmationView(PasswordResetConfirmView):
    """Gets new password from user and saves to database"""
    template_name = 'password_confirm.html'
    form_class = SetPasswordForm
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        # Update the user's password in the database
        form.save()
        return super().form_valid(form)


def accessKeyPurchaseView(request):
    """
    Create a new Access_Key instance associated with the
    IT_Personnel's school_id, but only if there is no active key already assigned to that school_id.
    """
    if request.method == 'GET': 
        existing_active_key = SchoolAccessKey.objects.filter(
            school=request.user.it_personnel.school,
            access_key__status='Active',
            access_key__expiry_date__gt=timezone.now()
        ).first()

        if existing_active_key:
            messages.warning(request, 'Your school already has an active access key.')
            return redirect('it_personnel_dashboard')
        
        new_access_key = Access_Key.objects.create(
            key=uuid.uuid4(),
            status='Active',
            date_of_procurement=timezone.now(),
            expiry_date=timezone.now() + timedelta(days=365)
        )
        SchoolAccessKey.objects.create(
            school=request.user.it_personnel.school,
            access_key=new_access_key
        )
        messages.success(request, f'New access key purchased: {new_access_key.key}')
        return redirect('it_personnel_dashboard')
    else:
        return HttpResponseBadRequest('Invalid request method')

# Micro-Focus Admin Pages
def accessKeyListView(request):
    """
    Fetch all Access_Key instances and display them
    """
    context = {}
    if request.method == 'GET':
        access_keys = AccessKey.objects.all()
        context['access_keys'] = [sak.access_key for sak in access_keys]
    return render(request, 'admin_dashboard.html', context)


#endpoint
class ActiveKeyAPIView(LoginRequiredMixin, View):

    def get(self, request, *args, **kwargs):
        # Extract email from the query parameters
        email = request.GET.get('email')
        if not email:
            return JsonResponse({'status': 400, 'message': 'Email is required.'}, status=400)
        
        try:
            # Find the school associated with the email
            school = School.objects.get(personnels__school_email=email)
            # Find the active access key for the school
            active_keys = SchoolAccessKey.objects.filter(
                school=school, access_key__status='Active'
            )
            if active_keys.exists():
                active_key = active_keys.first().access_key
                return JsonResponse({
                    'status': 200,
                    'key': active_key.key,
                    'date_of_procurement': active_key.date_of_procurement,
                    'expiry_date': active_key.expiry_date,
                })
            else:
                return JsonResponse({'status': 404, 'message': 'No active key found.'}, status=404)
        except School.DoesNotExist:
            return JsonResponse({'status': 404, 'message': 'School not found.'}, status=404)