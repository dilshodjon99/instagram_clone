from django.contrib.auth.password_validation import password_changed, validate_password
from rest_framework import serializers
from .models import *
from rest_framework.exceptions import ValidationError
from .utility import send_email, check_email_or_phone


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ('id',
                  'auth_type',
                  'auth_status')
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
        if value and User.objects.filter(email=value).exists():
            data = {
                "success": False,
                "message": "Bu email allaqachon ma'lumotlar bazasida bor"
            }
            raise ValidationError(data)
        elif value and User.objects.filter(phone=value).exists():
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
            data= {
                'message': 'Password do not match'
            }
            raise ValidationError(data)

        if password:
            validate_password(password)
            validate_password(confirm_password)

        return data

    def validate_username(self, username):
        if len(username) < 5 or len(username) > 20:
            data = {
                'message': "Username must be between 5 and 20 characters"
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
    instance.first_name = validated_data.get('firstname', instance.first_name)
    instance.last_name = validated_data.get('last_name', instance.last_name)
    instance.username = validated_data.get('username', instance.username)
    instance.password = validated_data.get('password', instance.password)

    if validated_data.get('password'):
        instance.set_password(validated_data.get('password'))

    if instance.auth_status in [CODE_VERIFIED, PHOTO_DONE]:
        instance.auth_status = DONE
    else:
        data = {
            'message': 'Auth status is invalid'
        }
        raise ValidationError(data)
    instance.save()
    return instance

