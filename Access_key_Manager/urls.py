"""
URL configuration for Access_key_Manager project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from app.views import ITPersonnelRegisterView, userLoginView, AdminDashboardView, ITPersonnelDashboardView, accessKeyPurchaseView, passwordResetView, PasswordResetConfirmationView, ActiveKeyAPIView

app_name = 'app'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', ITPersonnelRegisterView.as_view(), name='register'),
    path('login/', userLoginView.as_view(), name='login'),
    path('admin_dashboard/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('it_dashboard/', ITPersonnelDashboardView.as_view(), name='it_personnel_dashboard'),
    path('purchase-key/', accessKeyPurchaseView, name='accessKeyPurchase'),
    path('password-reset/', passwordResetView, name='password_reset'),
    path('password-confirm/<uidb64>/<token>/', PasswordResetConfirmationView.as_view(), name='password_confirm'),
    path('api/active-key/', ActiveKeyAPIView.as_view(), name='active_key_api'),
]
