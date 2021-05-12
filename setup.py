import sys
import os
import subprocess
import json

print("Welcome to the Phoneix SOC Reporting and Quick Analysing Tool")
print("Ozberk Akbas - 2021")

print("Setup will have 3 stepps. In the first step you need to add your api keys as they are asked.")
print("Next part of the setup process will be dependencies installation.")
print(" - Requests") 
print(" - Termcolor")

print("""You may also have questions about the project so type "Help" to the following question. """)

answer = str(input("Shall We Continue?[Yes/No/Help]:"))

if answer == "Yes":

    authkeyexch = str(input("XForce Exchange API Key:"))
    authpasswdexch = str(input("XForce Exchange API Password:"))
    vtapikey = str(input("Virus Toal API Key:"))
    abuseapikey = str(input("AbuseIP DB API Key:"))

    cred = {}
    cred["authkeyexch"] = authkeyexch
    cred["aauthpasswdexch"] = authpasswdexch
    cred["vtapikey"] = vtapikey
    cred["abuseapikey"] = abuseapikey

    with open("apicreds.json", "w") as credfile:
        json.dump(cred, credfile)

    try:
        os.system('uname -a')

        subprocess.check_call([sys.executable, "-m", "pip", "install", "termcolor"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    
    except:

        subprocess.call('powershell.exe pip3 install requests', shell=True)
        subprocess.call('powershell.exe pip3 install termcolor', shell=True)

    print("Installation Complete")
    x = input("Press Enter to Exit")

if answer == "No":
    x = input("Press Enter to Exit")
    sys.exit(0)

if answer == "Help":
    print("----------------------------------------------------")
    print("Requirements:")
    print("Termcolor: Termcolor is a python library for printing colored outputs on console screen like bash or powershell.")
    print("Requests: Requests is a python library for making http requests and processing the responses as codes or content.")
    print("""The program will ask you for your apikeys to use them for authorizating with the api's. It also store them inside a file called "apicreds.json". You can change them from there. """)
    print("Thank you for visiting this lonely help page.")
    print("----------------------------------------------------")
    sys.exit(0)
