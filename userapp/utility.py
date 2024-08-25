import re
import os
import threading
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework.exceptions import ValidationError
from twilio.rest import Client


email_regex = re.compile(r"^[a-zA-Z0-9_.±]+@[a-zA-Z0-9-]+.[a-zA-Z0-9-.]+$")
phone_regex = re.compile(r"^([+]?[\s0-9]+)?(\d{3}|[(]?[0-9]+[)])?([-]?[\s]?[0-9])+$")
username_regex = re.compile(r"^[a-zA-Z0-9]+([._]?[a-zA-Z0-9]+)*$")


def check_email_or_phone(email_or_phone):
    if re.fullmatch(phone_regex, email_or_phone):
        email_or_phone = "phone"
    elif re.fullmatch(email_regex, email_or_phone):
        email_or_phone = "email"

    else:
        data = {
            'success': False,
            'message': "Email or phone is not valid"
        }
        raise ValidationError(data)
    return email_or_phone


class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Email:

    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data['content_type'] == 'html':
            email.content_subtype = 'html'
        EmailThread(email).start()


def send_email(email, code):
    html_content = render_to_string('email/send_email.html', {'code': code})
    Email.send_email(
        {
            'subject': "Ro'yxatdan o'tish",
            'to_email': email,
            'body': html_content,
            'content_type': 'html'
        }
    )

# def send_phone_code(phone, code):
#     account_sid = os.environ["TWILIO_ACCOUNT_SID"]
#     auth_token = os.environ["TWILIO_ACCOUNT_TOKEN"]
#
#     client = Client(account_sid, auth_token)
#
#     message = client.messages.create(
#         to="+15558675309",
#         from_="+15017250604",
#         body="Hello from Python!")



