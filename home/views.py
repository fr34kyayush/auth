from django.shortcuts import render, redirect, HttpResponseRedirect, HttpResponse
from django.contrib.auth import authenticate, login as auth_login, logout
from django.contrib.auth.models import User
import random as rand
from django.views.decorators.csrf import csrf_exempt
from django.db import connection
import time
from datetime import datetime, timedelta
from django.contrib.auth.decorators import login_required
from django.conf import settings
import jwt
from jwt.exceptions import InvalidSignatureError
from django.views.decorators.cache import never_cache
from django.core.mail import send_mail
from django.contrib import messages
from .mail import sendmail

# Create your views here.
def generate_token(user):
    payload = {
        'user_id': user.id,
        'username': user.username,
        'exp': datetime.utcnow() + timedelta(seconds=settings.JWT_EXPIRATION_SECONDS)
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
    return token

def verify_token(token):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, InvalidSignatureError):
        return None

def signup(request):
    if request.method == "POST":
        mail = request.POST.get('email')
        passwd = request.POST.get('password')
        c_user = User.objects.create_user(username=mail, password=passwd)
        c_user.save()
        return redirect('correct')
    return render(request, "sign_up.html")

def login(request):
    try:
        if request.method == "POST":
            mail = request.POST.get('email')
            return HttpResponseRedirect('/password/?email={}'.format(mail))
    except:
        return redirect("wrong")
    return render(request, "login.html")

def wrong(request):
    return render(request, "wrong.html")

def correct(request):
    return render(request, "correct.html")

@never_cache
def dashboard(request):
    token = request.COOKIES.get('token')
    print(token)
    if token:
        payload = verify_token(token)
        if payload:
            # Token is valid
            user_id = payload.get('user_id')
            username = payload.get('username')
            # Use the user_id and username as required

            # Pass user_id and username to the template context
            context = {
                'user_id': user_id,
                'username': username
            }
            return render(request, "dashboard.html", context)

    # Token is invalid or not provided
    logout(request)  # Log out the user
    response = redirect("login")  # Redirect to the login page
    response.delete_cookie('token')  # Remove the token cookie from the response
    return response



def logout_view(request):
    logout(request)
    response = redirect('login')
    response.delete_cookie('token')
    return response

@csrf_exempt
def password(request):
    mail = request.GET.get('email')
    if request.method == "POST":
        try:
            passwd = request.POST.get('password')
            user = authenticate(request, username=mail, password=passwd)
            if user is not None:
                auth_login(request, user)
                token = request.COOKIES.get('token')

                if not token:
                    # Generate a new token
                    token = generate_token(user)

                response = redirect('dashboard')
                response.set_cookie('token', token)
                return response
            else:
                return redirect('wrong')
        except Exception as e:
            return redirect('wrong')
    return render(request, "password.html")


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(username=email)
        except User.DoesNotExist:
            user = None
        if user:
            otp = rand.randint(1000, 9999)
            request.session['reset_otp'] = otp
            request.session['reset_email'] = email
            sendmail(email,otp)
            return redirect('reset_password')
        else:
            return redirect('wrong')
    return render(request, 'forgot_password.html')

def reset_password(request):
    if request.method == 'POST':
        otp = int(request.POST.get('otp'))
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        session_otp = request.session.get('reset_otp')
        email = request.session.get('reset_email')
        if otp == session_otp and new_password == confirm_password:
            try:
                # Update the user's password
                user = User.objects.get(username=email)
                user.set_password(new_password)
                user.save()

                # Clear the session data
                del request.session['reset_otp']
                del request.session['reset_email']

                messages.success(request, 'Password reset successful. You can now login with your new password.')
                return redirect('login')
            except User.DoesNotExist:
                pass
        else:
            return redirect('forgot')

    return render(request, 'reset_password.html')