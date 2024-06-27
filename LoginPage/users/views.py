from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth.models import User
import re 

def register(request):
    if request.method == 'POST':
        name = request.POST.get('text')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Form validation
        if not name or not email or not password:
            messages.error(request, 'All fields are required.')
            return redirect('register')
        
        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email is already registered.')
            return redirect('register')
        
        if len(password) < 8:
            messages.error(request, 'Password should contain at least 8 characters.')
            return redirect('register')
        
        if not re.search("[a-z]", password):
            messages.error(request, 'Password should contain at least one lowercase letter.')
            return redirect('register')
        
        if not re.search("[A-Z]", password):
            messages.error(request, 'Password should contain at least one uppercase letter.')
            return redirect('register')
        
        if not re.search("[0-9]", password):
            messages.error(request, 'Password should contain at least one number.')
            return redirect('register')
        
        if not re.search("[_@#%$]", password):
            messages.error(request, 'Password should contain at least one special character.')
            return redirect('register')

        # All checks passed, create the user
        user = User.objects.create_user(username=email, password=password, email=email)
        user.save()
        messages.success(request, 'User created successfully.')
        return redirect('signin')  # Redirect to login page after successful registration
    else:
        return render(request, 'users/register.html')

def signin(request):
    context ={}
    
    if request.method == 'POST':
       
        email = request.POST['email']
        password = request.POST['password']
        
        user = authenticate(username = email, password = password)
        
        if user is not None:
           
            login(request, user)
            print(user.email)
            # fname = user.first_name                
            profile = User.objects.get(email = user.email)
            print(profile)
            return redirect('https://phoenixabscaie.netlify.app/')
        else:
            
            messages.error(request, "Invalid email or password. Please try again.")
            return render(request, "users/signin.html")

    return render( request, "users/signin.html")





def content(request):
    print('c')
    return render(request, 'users/content.html')
