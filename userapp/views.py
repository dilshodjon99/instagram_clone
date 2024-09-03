from rest_framework import generics, permissions, status
from .models import *
from .serializers import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from datetime import datetime
from rest_framework_simplejwt.views import TokenObtainPairView


# Create your views here.

class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = [permissions.AllowAny]  # hechqanday imkoniyatlarni cheklamaslik u-n


class VerifyAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = self.request.user
        code = self.request.data.get('code')

        self.check_verify(user, code)
        return Response(
            data={
                'success': True,
                'auth_status': user.auth_status,
                'access': user.token()['access'],
                'refresh': user.token()['refresh_token'],
            }
        )

    @staticmethod
    def check_verify(user, code):
        verify = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)
        if not verify.exists():
            data = {
                'message': 'Verification code is invalid',
            }
            raise ValidationError(data)
        else:
            verify.update(is_confirmed=True)

        if user.auth_status in [NEW]:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True


class GetNewVerifyCodeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        self.check_verification(user)
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)

        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
            # send_phone_code(user.phone_number, code)
        else:
            data = {
                'message': 'Invalid verification code',
            }
            raise ValidationError(data)

        return Response(
            data={
                'success': True,
                'auth_status': user.auth_status,
                'access': user.token()['access'],
                'refresh': user.token()['refresh_token'],
            }
        )

    @staticmethod
    def check_verification(user):
        verify = user.verify_codes.filter(expiration_time__gte=datetime.now(), is_confirmed=False)
        if verify.exists():
            data = {
                'message': 'Kodingiz ishlatish uchun yaroqli',
            }
            raise ValidationError(data)


class ChangeUserView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangeUserSerializer
    http_method_names = ['put', 'patch', ]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeUserView, self).update(request, *args, **kwargs)
        data = {
            'success': True,
            'message': 'User updated',
            'auth_status': self.request.user.auth_status,
        }
        return Response(data)

class ChangePhotoView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, *args, **kwargs):
        serializer = ChangePhotoSerializer(data=request.data)
        if serializer.is_valid():
            user = self.request.user
            serializer.update(user, serializer.validated_data)
            return Response({
                "message": "User photo updated",
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer
