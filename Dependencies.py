# # -*- coding: utf-8 -*-
# import subprocess
# import sys

# print("Dependencies:")
# print(" - Requests")
# print(" - Termcolor")

# answer = input("Dependencies will be installed. Do you want to proceed? [Yes/No]:")


# if answer == "Yes":
#         os = input("What is your operating system? [Windows / Linux]")
#         if os == "Windows":
#                 try:
#                         subprocess.call('powershell.exe pip3 install requests', shell=True)
#                 except:
#                         raise
#                         sys.exit(0)
#                 try:
#                         subprocess.call('powershell.exe pip3 install termcolor', shell=True)
#                 except:
#                         raise
#                         sys.exit(0)
		
#                 print("İnstallation complete. You may use the script at ease.")

#         if os == "Linux":
#                 try:
#                         subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
#                 except:
#                         raise
#                         sys.exit(0)
#                 try:
#                         subprocess.check_call([sys.executable, "-m", "pip", "install", "termcolor"])
#                 except:
#                         raise
#                         sys.exit(0)
		
                
#                 print("İnstallation complete. You may use the script at ease.") 
                        
# else: 
# 	print("Bye")
# 	SystemExit

# k= input("Press Enter to exit") 
