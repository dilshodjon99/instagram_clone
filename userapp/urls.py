from django.urls import path
from .views import CreateUserView, VerifyAPIView, ChangeUserView, GetNewVerifyCodeView, ChangePhotoView, LoginView


urlpatterns = [
    path('signup/', CreateUserView.as_view()),
    path('verify/', VerifyAPIView.as_view()),
    path('new_verify/', GetNewVerifyCodeView.as_view()),
    path('register/', ChangeUserView.as_view()),
    path('change_photo/', ChangePhotoView.as_view()),
    path('login/', LoginView.as_view())
]
