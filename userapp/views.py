from django.shortcuts import render
from rest_framework import generics, permissions
from .models import User, UserConfirmation
from .models import ORDINARY_USER, MANAGER, ADMIN, VIA_EMAIL, VIA_PHONE, NEW, COD_VERIFIED, DONE
from .serializers import SignUpSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from datetime import datetime


class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    permissions_class = [permissions.AllowAny]


class VerifyAPIView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, *args, **kwargs):
        user = self.request.user
        code = self.request.data.get('code')

        self.check_verify(user, code)
        return Response(
                data = {
                    'success': True,
                    'auth_status': user.auth_status,
                    'access': user.token()['access'],
                    'refresh': user.token()['refresh_token']
                }
                )

    @staticmethod
    def check_verify(user, code):
        verify = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)
        if not verify.exists():
            data = {
                'message': 'Verify code is invalid',
            }
            raise ValidationError(data)
        else:
            verify.update(is_confirmed=True)

        if user.auth_status in [NEW]:
            user.auth_status = COD_VERIFIED
            user.save()
        return True


