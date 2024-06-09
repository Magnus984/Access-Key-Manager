from django.db import models
from django.contrib.auth.models import User


class IT_Personnel(models.Model):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.CharField(max_length=30)
    school_id = models.ForeignKey(
        School, on_delete=models.CASCADE
        )


class Admin(models.Model):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.CharField(max_length=30)


class School(models.Model):
    name = models.CharField(max_length=40)


class Access_Key(models.Model):
    key = models.CharField(max_length=45, unique=True)
    status = models.TextChoices(
        'Active', 'revoked', 'expired'
    )
    date_of_procurement = models.DateTime()
    expiry_date = models.DateTime()
    school_id = models.ForeignKey(
        School, on_delete=models.CASCADE
    )

class Custom_User(User):
    access_key_id = models.OneToOneField(
        Access_Key, on_delete = models.CASCADE
    )