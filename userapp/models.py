from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
import uuid
import random
from datetime import datetime, timedelta
from rest_framework_simplejwt.tokens import RefreshToken

ORDINARY_USER, MANAGER, ADMIN = ('ordinary_user', 'manager', 'admin')
VIA_EMAIL, VIA_PHONE = ('via_email', 'via_phone')
NEW, CODE_VERIFIED, DONE, PHOTO_DONE, FORGET_PASS, NEW_PHONE = ('new', 'code_verified', 'done',
                                                                'photo_done', 'forget_password', 'new_phone')


class BaseModel(models.Model):
    id = models.URLField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    #Clas ichidagi ma'lumotlarni maxfiy saqlayidi  abstract = True

    class Meta:
        abstract = True


class User(AbstractUser, BaseModel):
    USER_ROLES = (
        (ORDINARY_USER, ORDINARY_USER),
        (MANAGER, MANAGER),
        (ADMIN, ADMIN),
    )

    AUTH_TYPE_CHOICE = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE),
    )

    AUTH_STATUS = (
        (NEW, NEW),
        (CODE_VERIFIED, CODE_VERIFIED),
        (DONE, DONE),
    )

    user_role = models.CharField(max_length=50, choices=USER_ROLES, default=ORDINARY_USER)
    auth_type = models.CharField(max_length=50, choices=AUTH_TYPE_CHOICE)
    auth_status = models.CharField(max_length=50, choices=AUTH_STATUS, default=NEW)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone = models.CharField(max_length=20, null=True, blank=True)
    photo = models.ImageField(upload_to='user_photos/', null=True, blank=True,
                              validators=[FileExtensionValidator(['jpg', 'png', 'jpeg', 'webp'])])

    def __str__(self):
        return self.username

    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def create_verify_code(self, verify_type):
        code = "".join(str(random.randint(1, 1000)%10) for _ in range(4))
        UserConfirmation.objects.create(
            user_id=self.id,
            code=code,
            verify_type=verify_type)
        return code

    def check_username(self):
        if not self.username:
            temp_username = f"user-{uuid.uuid4().__str__().split('-')[-1]}"
            while User.objects.filter(username=temp_username):
                temp_username = f'{temp_username} {random.randint(1, 9)}'
            self.username = temp_username

    def check_email(self):
        if self.email:
            normalize_email = self.email.lower()
            self.email = normalize_email

    def check_pass(self):
        if not self.password:
            temp_password = f'pass-{uuid.uuid4().__str__().split("-")[-1]}'
            self.password = temp_password

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sh256'):
            self.set_password(self.password)

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "access": str(refresh.access_token),
            "refresh_token": str(refresh)
        }

    def save(self, *args, **kwargs):
        self.clean()
        super(User, self).save(*args, **kwargs)

    def clean(self):
        self.check_email()
        self.check_username()
        self.check_pass()
        self.hashing_password()


PHONE_EXPIRE = 2
EMAIL_EXPIRE = 5


class UserConfirmation(BaseModel):
    TYPE_CHOICES = ((VIA_PHONE, VIA_PHONE),
                    (VIA_EMAIL, VIA_EMAIL),)
    code = models.CharField(max_length=4)
    verify_type = models.CharField(max_length=50, choices=TYPE_CHOICES)
    user = models.ForeignKey('User', on_delete=models.CASCADE, related_name='verify_codes')
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user} {self.code}'

    def save(self, *args, **kwargs):
        if self.verify_type == VIA_EMAIL:
            self.expiration_time = datetime.now() + timedelta(minutes=EMAIL_EXPIRE)

        else:
            self.expiration_time = datetime.now() + timedelta(minutes=PHONE_EXPIRE)

        super(UserConfirmation, self).save(*args, **kwargs)
