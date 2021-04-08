# -*- coding: utf-8 -*-
import subprocess
import sys

print("Dependencies:")
print(" - Requests")
print(" - Termcolor")

answer = input("Dependencies will be installed. Do you want to proceed? [Y/N]:")

if answer == "Y":
	try:
		subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
	except:
		raise
		SystemExit
	try:
		subprocess.check_call([sys.executable, "-m", "pip", "install", "termcolor"])
	except:
		raise
		SystemExit
		
	print("İnstallation complete. You may use the script at ease.")
elif answer == "Yes":
	try:
		subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
	except:
		raise
		SystemExit
	try:
		subprocess.check_call([sys.executable, "-m", "pip", "install", "termcolor"])
	except:
		raise
		SystemExit
		
	print("İnstallation complete. You may use the phoneix at ease.")
else: 
	print("Bye")
	SystemExit

k= input("Press Enter to exit") 
