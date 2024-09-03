from rest_framework import serializers
from .models import *
from rest_framework.exceptions import ValidationError, PermissionDenied
from .utility import send_email, check_email_or_phone, check_user_type
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            'id',
            'auth_type',
            'auth_status',
        )
        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': False},
            'auth_status': {'read_only': True, 'required': False},
        }

    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)

        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)

        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
            # send_phone_code(user.phone_number, code)
        user.save()
        return user

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        return data

    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('email_phone_number')).lower()
        input_type = check_email_or_phone(user_input)

        if input_type == "phone":
            data = {
                "phone_number": user_input,
                "auth_type": VIA_PHONE
            }

        elif input_type == "email":
            data = {
                "email": user_input,
                "auth_type": VIA_EMAIL
            }
        else:
            data = {
                'success': False,
                'message': "You must send  phone number"
            }
            raise ValidationError(data)

        return data

    def validate_email_phone_number(self, value):
        value = value.lower()
        input_type = check_email_or_phone(value)
        if input_type == 'email' and User.objects.filter(email=value).exists():
            data = {
                "success": False,
                "message": "Bu email allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        elif input_type == 'phone' and User.objects.filter(phone_number=value).exists():
            data = {
                "success": False,
                "message": "Bu telefon raqami allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        return value

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())

        return data


class ChangeUserSerializer(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)

        if password != confirm_password:
            data = {
                'message': 'Passwords do not match'
            }
            raise ValidationError(data)

        if password:
            validate_password(password)
            validate_password(confirm_password)

        return data

    def validate_username(self, username):
        if len(username) < 5 or len(username) > 20:
            data = {
                'message': 'Username must be between 5 and 20 characters'
            }
            raise ValidationError(data)

        if username.isdigit():
            data = {
                'message': 'Username must be unique'
            }
            raise ValidationError(data)

        if User.objects.filter(username=username).exists():
            data = {
                'message': 'Username already taken'
            }
            raise ValidationError(data)

        return username

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', instance.username)
        instance.password = validated_data.get('password',
                                               instance.password)

        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))

        if instance.auth_status in [CODE_VERIFIED, DONE, PHOTO_DONE]:
            instance.auth_status = DONE

        else:
            data = {
                'message': 'Auth status is invalid'
            }
            raise ValidationError(data)
        instance.save()
        return instance


class ChangePhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo')

        if photo and instance.auth_status in [DONE, PHOTO_DONE]:
            instance.photo = photo
            instance.auth_status = PHOTO_DONE
            instance.save()

        else:
            data = {
                'message': 'Auth status is invalid'
            }
            raise ValidationError(data)
        return instance


class LoginSerializer(TokenObtainPairSerializer):
    def __init__(self, request=None, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['userinput'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False, read_only=True)

    def auth_validate(self, data):
        user_input = data.get('userinput')
        if check_user_type(user_input) == 'username':
            username = user_input

        elif check_user_type(user_input) == 'email':
            user = self.get_user(
                email__iexact=user_input)
            username = user.username

        elif check_user_type(user_input) == 'phone':
            user = self.get_user(phone_number=user_input)
            username = user.username

        else:
            data = {
                'success': False,
                'message': "Siz email, username yoki telefon raqami jonatishingiz kerak"
            }
            raise ValidationError(data)

        authentication_kwargs = {
            self.username_field: username,
            'password': data['password']
        }
        curent_user = User.objects.filter(username__iexact=username).first()

        if curent_user is not None and curent_user.auth_status in [NEW, CODE_VERIFIED]:
            raise ValidationError(
                {
                    'success': False,
                    'message': 'Siz royhatdan otmagansiz'
                }
            )
        user = authenticate(**authentication_kwargs)
        if user is not None:
            self.user = user
        else:
            raise ValidationError(
                {
                    'success': False,
                    'message': 'Username yoki pasvord hato'
                }
            )

    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, PHOTO_DONE]:
            raise PermissionDenied("Siz login qilolmaysiz ruhsatingiz yoq")
        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        return data

    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        if not users.exists():
            raise ValidationError(
                {
                    'message': 'User not found'
                }
            )
        return users.first()