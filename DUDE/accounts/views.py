from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from .forms import UserRegisterForm

from django.contrib.auth.models import Group


# Create your views here.


############################################### Register #####################################################

def not_logged_in(user):
    return not user.is_authenticated


@user_passes_test(not_logged_in, login_url="/feast")
def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account has been created for {username}!, Now You can able to logIn ')
            return redirect('login')
    else:
        form = UserRegisterForm()
    return render(request, 'accounts/register.html', {'form': form})


########################################## LOGIN ############################################################


def user_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            uname = form.cleaned_data['username']
            upass = form.cleaned_data['password']
            user = authenticate(username=uname, password=upass)
            if user is not None:
                login(request, user)
                messages.success(request, 'You logged in successfully')
                return redirect('/feast')
        else:
            return render(request, 'accounts/login.html', {'form': form})

    else:
        form = AuthenticationForm()
        return render(request, 'accounts/login.html', {'form': form})


################################################### LOGOUT #################################################

def user_logout(request):
    form = logout(request)
    return redirect('login')
