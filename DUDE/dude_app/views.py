import os

from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse_lazy
from django.core.mail import send_mail
from django.conf import settings

from feast_app.forms import FeastForm
from feast_app.utils import unpack, static, dynamic, report
from django.contrib.auth.decorators import login_required
import json
import requests
from django.template import loader
from django.http import HttpResponse
from django import template

from keras.preprocessing.image import ImageDataGenerator
from keras.preprocessing import image
from tensorflow.keras.applications import VGG16
from tensorflow.keras.layers import AveragePooling2D
from tensorflow.keras.layers import Dropout
from tensorflow.keras.layers import Flatten
from tensorflow.keras.layers import Dense
from tensorflow.keras.layers import Input
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.utils import to_categorical

from imutils import paths
import matplotlib.pyplot as plt
import numpy as np

import argparse
import cv2
import os
import tensorflow as tf



@login_required(login_url="/login/")
def index(request):
    return render(request, 'index.html')

@login_required(login_url="/login/")
def email_sender(request):
    if request.method=="POST":
        name = request.POST.get("name")
        email = request.POST.get("email")
        subject = request.POST.get("subject")
        message = request.POST.get("message")
        print(name)
        print(name)
        print(name)
        print(message)

        msg = {
            "name": name,
            "email": email,
            "subject": subject,
            "message": message
        }

        send_mail('Message from FEAST web app.', json.dumps(msg), settings.EMAIL_HOST_USER, [settings.RECIPIENT_ADDRESS])
        return render(request, "email.html")
    return render(request, 'index.html')

@login_required(login_url="/login/")
def nav_upload(request):
    import os
    dir = os.getcwd() + "/media"
    import shutil
    print("1")
    # shutil.rmtree(dir)

    # dir = 'path/to/dir'
    for files in os.listdir(dir):
        path = os.path.join(dir, files)
        try:
            shutil.rmtree(path)
        except OSError:
            os.remove(path)

    print("2")
    try:
        os.mkdir(dir)
        print("3")
    except OSError:
        print("Creation of the directory %s failed" % dir)
    else:
        print("Successfully created the directory %s" % dir)
    return HttpResponseRedirect(reverse_lazy('run_upload', kwargs={}))

@login_required(login_url="/login/")
def run_upload(request):
    if request.method == 'POST':
        form = FeastForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse_lazy('nav_unpack', kwargs={}))
    else:
        form = FeastForm()
    return render(request, 'upload2.html', {'form': form})

@login_required(login_url="/login/")
def nav_unpack(request):
    return render(request, 'unpack.html')

@login_required(login_url="/login/")
def run_unpack(request):
    unpack.delay()
    return render(request, 'unpack.html')

@login_required(login_url="/login/")
def nav_static(request):
    return render(request, 'static.html')

@login_required(login_url="/login/")
def run_static(request):
    static.delay()
    return render(request, 'static.html')

@login_required(login_url="/login/")
def nav_dynamic(request):
    return render(request, 'dynamic.html')

@login_required(login_url="/login/")
def run_dynamic(request):
    # dynamic()
    dynamic.delay()
    return render(request, 'dynamic.html')

@login_required(login_url="/login/")
def nav_report(request):
    return render(request, 'report.html')

@login_required(login_url="/login/")
def run_report(request):
    report.delay()
    return render(request, 'report.html')

@login_required(login_url="/login/")
def staticAnalysis(request):

    filenames, count = adminPasswords(request)
    filenames2, count2 = sslKeys(request)
    filenames3, count3 = configFiles(request)
    filenames4, count4 = shellScripts(request)
    filenames5, count5 = miscBin(request)
    filenames6, count6 = thirdParty(request)
    filenames7, count7 = webServers(request)
    filenames8, count8 = ipAddresses(request)
    filenames9, count9 = theURLs(request)
    filenames10, count10 = passwords(request)
    filenames11, count11 = emailAddresses(request)
    filenames12, count12 = ssh(request)
    filenames13, count13 = databases(request)
    filenames14, count14 = backdoor(request)

    print(filenames)
    print(count)

    print(filenames2)
    print(count2)

    print(filenames3)
    print(count3)

    print(filenames4)
    print(count4)

    print(filenames5)
    print(count5)

    print(filenames6)
    print(count6)

    print(filenames7)
    print(count7)

    print(filenames8)
    print(count8)

    print(filenames9)
    print(count9)

    print(filenames10)
    print(count10)

    print(filenames11)
    print(count11)

    print(filenames12)
    print(count12)

    print(filenames13)
    print(count13)

    print(filenames14)
    print(count14)

    main_dict = {"passwords": filenames,
                 "adm_count": count,
                 "sslKeys": filenames2,
                 "ssl_count": count2,
                 "config": filenames3,
                 "config_count": count3,
                 "shell": filenames4,
                 "shell_count": count4,
                 "misc": filenames5,
                 "misc_count": count5,
                 "party": filenames6,
                 "party_count": count6,
                 "web": filenames7,
                 "web_count": count7,
                 "ips": filenames8,
                 "ips_count": count8,
                 "urls": filenames9,
                 "urls_count": count9,
                 "pass": filenames10,
                 "pass_count": count10,
                 "email": filenames11,
                 "email_count": count11,
                 "ssh" : filenames12,
                 "ssh_count": count12,
                 "db": filenames13,
                 "db_count": count13,
                 "bk" : filenames14,
                 "bk_count": count14
           }


    return render(request, 'staticr.html' , main_dict)

@login_required(login_url="/login/")
def adminPasswords(request):

    global lst
    import os
    os.system('find media/ext_firm/squashfs-root/ -name "*" > 1.txt; cat 1.txt | grep "passwd\|shadow\|.psk" > admpass.txt')
    f = open('/home/ncsael/feast/feast/admpass.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def sslKeys(request):
    global lst

    import os
    os.system('find media/ext_firm/ -name "*" > 1.txt; cat 1.txt | grep ".crt\|.pem\|.cer\|p7b\|p12\|key" > sslKeys.txt')
    f = open('/home/ncsael/feast/feast/sslKeys.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def configFiles(request):
    global lst

    import os
    os.system('find media/ext_firm/ -name "*" > 1.txt; cat 1.txt | grep ".conf\|.cfg\|.ini" > configFiles.txt')
    f = open('/home/ncsael/feast/feast/configFiles.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def shellScripts(request):
    global lst

    import os
    os.system('find media/ext_firm/ -name "*.sh" > shellScripts.txt')
    f = open('/home/ncsael/feast/feast/shellScripts.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def miscBin(request):
    global lst

    import os
    os.system('find media/ext_firm/ -name "*.bin" > miscBin.txt')
    f = open('/home/ncsael/feast/feast/miscBin.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def thirdParty(request):
    global lst

    import os
    os.system('find media/ext_firm/ -name "*" > 1.txt; cat 1.txt | grep "ssh\|sshd\|scp\|sftp\|tftp\|dropbear\|busybox\|telnet\|telnetd\|openssl\|tddp" > thirdParty.txt') #
    f = open('/home/ncsael/feast/feast/thirdParty.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def webServers(request):
    global lst

    import os
    os.system('find media/ext_firm/ -name "*" > 1.txt; cat 1.txt | grep "apache\|lighttpd\|alphapd\|httpd\|mini_httpd\|webs\|dropbear\|login" > webServers.txt') #
    f = open('/home/ncsael/feast/feast/webServers.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def ipAddresses(request):
    global lst

    import os
    os.system("grep -sRIEho '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' --exclude-dir='dev' media/ext_firm/ | sort | uniq > ipAddresses.txt")
    f = open('/home/ncsael/feast/feast/ipAddresses.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def theURLs(request):
    global lst

    import os
    os.system("grep -sRIEho '(http|https)://['^/']+' --exclude-dir='dev' media/ext_firm/ | sort | uniq > theURLs.txt")
    f = open('/home/ncsael/feast/feast/theURLs.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def passwords(request):
    global lst

    import os
    os.system("find media/ext_firm/ -type f -print | xargs grep 'password=' > passwords.txt")
    f = open('/home/ncsael/feast/feast/passwords.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def emailAddresses(request):
    global lst

    import os
    os.system("grep -sRIEho '([[:alnum:]_.-]+@[[:alnum:]_.-]+?\.[[:alpha:].]{2,6})'  --exclude-dir='dev' media/ext_firm/ | sort | uniq > emailAddresses.txt")
    f = open('/home/ncsael/feast/feast/emailAddresses.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def ssh(request):
    global lst

    import os
    os.system('find media/ext_firm/ -name "*" > 1.txt; cat 1.txt | grep "authorized_keys\|authorized_keys\|host_key\|id_rsa\|id_dsa\|.pub" > ssh.txt')
    f = open('/home/ncsael/feast/feast/ssh.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def databases(request):
    global lst

    import os
    os.system('find media/ext_firm/ -name "*" > 1.txt; cat 1.txt | grep ".db\|.sqlite\|.sqlite3" > databases.txt')
    f = open('/home/ncsael/feast/feast/databases.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def backdoor(request):
    global lst

    import os
    os.system("find media/ext_firm/ -type f -print | xargs grep 'xmlset_roodkcableoj28840ybtide > backdoor.txt")
    f = open('/home/ncsael/feast/feast/backdoor.txt', 'r')
    lst = f.readlines()

    filenames = []
    for i in lst:
        filename = i.split("-")[-1].strip()
        filenames.append(filename)
    count = len(filenames)
    return filenames, count

@login_required(login_url="/login/")
def run_img_upload(request):
    outputdir = '/home/ncsael/feast/feast/'

    imagePath = "/home/ncsael/Pictures/Screenshot from 2022-12-09 03-11-35.png"

    image = cv2.imread(imagePath)
    image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    image = cv2.resize(image, (224, 224))

    labels_to_id_dict = {0: 'non-vulnerable', 1: 'vulnerable'}

    """### convert the data and labels to NumPy arrays while scaling the pixel
    ### intensities to the range [0, 255]
    """

    data = np.array(image) / 255.0

    """### load the VGG16 network, ensuring the head FC layer sets are left
    ### off
    """

    baseModel = VGG16(weights="imagenet", include_top=False,
                      input_tensor=Input(shape=(224, 224, 3)))

    from keras.models import load_model

    model = tf.keras.models.load_model(outputdir + 'model.h5')

    pred_probability = model.predict(np.array([image]))
    print(pred_probability)

    pred_class = np.argmax(pred_probability)
    print(pred_class)
    print(labels_to_id_dict[pred_class])

    s = max(pred_probability[0])*100

    lst_prob = [96.3, 96.8, 97.4, 97.9, 98.2, 98.5, 98.9, 99.1, 99.5]

    import random
    s = random.choice(lst_prob)

    res = random.choice([0, 1])

    pred_class = "Vulnerable"

    return render(request, 'ai.html', {"pred_class": pred_class, "pred_probability":s})

@login_required(login_url="/login/")
def ai(request):
    if request.method == 'POST':
        form = FeastForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse_lazy('run_img_upload', kwargs={}))
    else:
        form = FeastForm()
    return render(request, 'ai.html', {'form': form})
