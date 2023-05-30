from django.shortcuts import render
from .models import Repository
from django.db import connection
from datetime import datetime
from django.template import RequestContext
from pathlib import Path
import os
import requests

import smtplib
import json

import webbrowser
import re
# Create your views here.


def admin(request):
    return render(request, admin.site.urls)


def index(request):
    return render(request, 'index.html')

def get_started(request):
    return render(request,'get_started.html')

def result(request):
    if request.method == "POST":
        manufacturer = request.POST["manufacturer"]
        title = request.POST["title"]
        version = request.POST["version"]
        updates = set()
        print(manufacturer)
        print(title)
        print(version)
        print("END USER")

        with connection.cursor() as cursor:
            cursor.execute(f'''SELECT version FROM repository_repository WHERE
            manufacturer="{manufacturer}" AND title="{title}" AND version="{version}"''')

            row_versions = cursor.fetchall()
            try:
                    if row_versions:
                        cursor.execute(f'''SELECT manufacturer, title, version, link, download_url FROM repository_repository WHERE
                                    manufacturer="{manufacturer}" ''')
                        all_products = cursor.fetchall()
                        for i in all_products:
                            if str(manufacturer) == "Tplink":
                                v1 = i[2]
                                v2 = version

                                try:
                                    database_test = v1.split(" ")
                                    user_test = v2.split(" ")

                                    database_t = re.search(r'[V|v|Ver]\s*([\d.|\d_]+)', database_test[-1]).group(1)
                                    user_t = re.search(r'[V|v|Ver]\s*([\d.|\d_]+)', user_test[-1]).group(1)

                                    database_t = database_t.split("_")
                                    user_t = user_t.split("_")

                                    database_result = ""
                                    user_result = ""

                                    for res in database_t:
                                        database_result = database_result + res

                                    for res in user_t:
                                         user_result = user_result + res

                                    # database_result = database_t[0] + database_t[1]
                                    # user_result = user_t[0] + user_t[1]

                                    print("End Database " + str(database_result))
                                    print("End User "+str(user_result))

                                    if user_result < database_result and title == i[1]:
                                        updates.add(i)
                                        print("need to update")
                                except:
                                    print("Exception on version: " + str(v1))

                            elif str(manufacturer) == "Tenda":
                                v1 = i[2]
                                v2 = version

                                try:
                                    database_test = v1.split(" ")
                                    user_test = v2.split(" ")

                                    database_t = re.search(r'[V|v]\s*([\d.]+)', database_test[-1])
                                    user_t = re.search(r'[V|v]\s*([\d.]+)', user_test[-1])

                                    database_t = database_t[1]
                                    user_t = user_t[1]

                                    database_t = database_t.split(".")
                                    user_t = user_t.split(".")

                                    database_result = ""
                                    user_result = ""

                                    for res in database_t:
                                        database_result = database_result + res

                                    for res in user_t:
                                        user_result = user_result + res

                                    # database_result = database_t[0] + database_t[1] + database_t[2] + database_t[3]
                                    # user_result = user_t[0] + user_t[1] + user_t[2] + user_t[3]

                                    print(database_result)
                                    print(user_result)

                                    if user_result < database_result and title == i[1]:
                                        updates.add(i)
                                        print("need to update")
                                except:
                                    print("Exception on version: " + str(v1))

                            elif str(manufacturer) == "Dlink":
                                v1 = i[2]
                                v2 = version

                                try:
                                    database_t = re.search(r"\d+(\.\d+)+", v1)
                                    user_t = re.search(r"\d+(\.\d+)+", v2)


                                    database_t = database_t[0]
                                    user_t = user_t[0]

                                    database_t = database_t.split(".")
                                    user_t = user_t.split(".")

                                    print("Database Entry: " + str(database_t))
                                    print("User Entry: " + str(user_t))

                                    database_result = ""
                                    user_result = ""

                                    for res in database_t:
                                        database_result = database_result + res

                                    for res in user_t:
                                        user_result = user_result + res


                                    # database_result = database_t[0] + database_t[1]
                                    # user_result = user_t[0] + user_t[1]

                                    print("Database Result: " + str(database_result))
                                    print("User Result: " + str(user_result))

                                    if user_result < database_result and title == i[1]:
                                        updates.add(i)
                                        print("need to update")
                                except:
                                    print("Exception on version: " + str(v1))

                            elif str(manufacturer) == "Linksys":
                                v1 = i[2]
                                v2 = version
                                try:
                                    database_t = re.search(r"\d+(\.\d+)+",v1)
                                    user_t = re.search(r"\d+(\.\d+)+",v2)

                                    database_t = database_t[0]
                                    user_t = user_t[0]

                                    database_t = database_t.split(".")
                                    user_t = user_t.split(".")

                                    print("Database Entry: " + str(database_t))
                                    print("User Entry: " + str(user_t))

                                    database_result = ""
                                    user_result = ""

                                    for res in database_t:
                                        database_result = database_result + res

                                    for res in user_t:
                                        user_result = user_result + res

                                    # database_result = database_t[0] + database_t[1]
                                    # user_result = user_t[0] + user_t[1]

                                    print("Database Result: " + str(database_result))
                                    print("User Result: " + str(user_result))

                                    if user_result < database_result and title == i[1]:
                                        updates.add(i)
                                        print("need to update")
                                except:
                                    print("Exception on version: " + str(v1))

                        updates = list(updates)
                        print(updates)
                        return render(request, 'final_result.html',{'updates':updates})
            except Exception as ex:
                print(ex)

        if str(manufacturer) == "Tplink":
            print("tplink")
            return render(request,'index.html')
        elif str(manufacturer) == "Tenda":
            print("tenda")
            return render(request,'index.html')
        elif str(manufacturer) == "Dlink":
            print("Dlink")
            return render(request,'index.html')
        elif str(manufacturer) == "Linksys":
            return render(request,'index.html')
    return render(request,'index.html')