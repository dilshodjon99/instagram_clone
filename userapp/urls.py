from django.urls import path
from .views import CreateUserView, VerifyAPIView, GetVerifyCodeView, ChangeUserView


urlpatterns = [
    path('signup/', CreateUserView.as_view()),
    path('verify/', VerifyAPIView.as_view()),
    path('new_verify/', GetVerifyCodeView.as_view()),
    path('register/', ChangeUserView.as_view())
]
