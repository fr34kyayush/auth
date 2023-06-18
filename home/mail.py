from django.core.mail import send_mail
from django.conf import settings

def sendmail(email,otp):
    subject = "Otp"
    message = f'This is your otp for changing your password {otp}'
    email_from = settings.EMAIL_HOST_USER
    list = [email]
    send_mail(subject,message,email_from,list)
    return True
