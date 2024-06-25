from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password


class microFocusAdmin(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.CharField(max_length=30)
    password = models.CharField(max_length=255, default='passwd')

    def set_password(self, raw_password):
        self.password = make_password(raw_password)


class School(models.Model):
    name = models.CharField(max_length=40)



class IT_Personnel(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.CharField(max_length=30)
    school_email = models.CharField(max_length=30, default='school_name@gmail.com')
    password = models.CharField(max_length=255, default='passwd')
    school_name = models.CharField(max_length=40)
    school = models.ForeignKey(
        School, on_delete=models.CASCADE,
        related_name='personnels'
        )

    def set_password(self, raw_password):
        self.password = make_password(raw_password)



class Access_Key(models.Model):
    key = models.CharField(max_length=45, unique=True)
    status = models.CharField(
        max_length=10,
        choices=models.TextChoices('STATUS', 'Active Revoked Expired'),
        default='Active'
    )
    date_of_procurement = models.DateTimeField()
    expiry_date = models.DateTimeField()


class SchoolAccessKey(models.Model):
    school = models.ForeignKey(
        School, on_delete=models.CASCADE, related_name='school_access_keys'
        )
    access_key = models.ForeignKey(
        Access_Key, on_delete=models.CASCADE, related_name='associated_schools'
        )
    date_assigned = models.DateTimeField(auto_now_add=True)