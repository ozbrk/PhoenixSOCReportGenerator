## File Analysis Tool --- OZBERK AKBAS
## 02.04.2020
## The program intended to analyze the given IP adress, hash value, file or file name given by user with IBM X-Force Exchange, Virus Total and Abuse IP DB
## The results will printed out as a report when everything is done and finished.

# IMPORTS ##########################################################################################################################
# try:
from __future__ import print_function
import csv
from email.header import Header
import enum
from genericpath import exists
import sys
import argparse
import requests
import json
import re
import time
sys.path.append(".")
from ibmip import reputationtool
from abuseipdb import AbuseIPDB
from vthashcheck import virustotalhashcheck
from ibmhashcheck import ibmhashcheck
from vtipcheck import vtipcheck
from ibmurl import *
from vturlcheck import virustotalurlcheck
import os 
import pathlib
import pandas as pd

# except:
# 	print("""[ERR] Dependencies haven't met! Run the setup.py first with the following command: "python3 setup.py" """)
# 	sys.exit(0)

#####################################################################################################################################

# PUT YOUR APIKEYS HERE! ############################################################################################################

""" IBM API KEY AND PASSWD """
try:
	with open("apicreds.json") as read_file:
		cred = json.loads(read_file.read())
except:
    raise

with open("apicreds.json") as read_file:
    cred = json.loads(read_file.read())

authkeyexch = str(cred["authkeyexch"])
authpasswdexch = str(cred["authpasswdexch"])
vtapikey = str(cred["vtapikey"])
abuseapikey = str(cred["abuseapikey"])

# Go IBM X For Exchange and retrive your api key and password from https://exchange.xforce.ibmcloud.com/settings/api

# Go Virustotal and register for your free apikey. Retrive it from https://www.virustotal.com/gui/user/<yourusername>/apikey

# Go AbuseipDB and retrieve your freeapikey from https://www.abuseipdb.com/account/api#

#####################################################################################################################################


# INTERNAL FUNCTIONS ################################################################################################################

# urlcheckadapter function have created for performing a loop against the "queued" response code 
def virustotalurlcheckadapter(resultid, vtheaders):
	analysisrequest = requests.get(f"https://www.virustotal.com/api/v3/analyses/{resultid}", headers=vtheaders)
	analysisresult = analysisrequest.json()
	if analysisresult["data"]["attributes"]["status"] == "queued":
		print("Status is in a queue. The script will retry in 5 seconds.")
		time.sleep(5)
		virustotalurlcheckadapter(resultid, vtheaders)
	else:
		resultprocess = virustotalurlcheck(analysisresult)
		resultprocess.vturlcheck()


# Command Line Parser ###############################################################################################################


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--filehash" , metavar = 'filehash' , type=str, help="type desired file hash")
parser.add_argument("-ip", "--ipaddr", metavar='ip' , help="type desired ip adress for check")
parser.add_argument("-u", "--url", help="type desired url")
parser.add_argument("-ex", "--exchange", help="Toogle IBM X-Force Exchange Check" , action="store_true")
parser.add_argument("-exp", "--export", help="Toogle Export Mode ForIBM X-Force Exchange Check" , action="store_true")
parser.add_argument("-fe", "--fileread", help="Toogle File Export Mode ForIBM X-Force Exchange Check" , action="store_true")
parser.add_argument("-vt", "--virustotal", help="Toogle Virus Total Check" , action="store_true")
parser.add_argument("-ab", "--abuseipdb", help="Toogle Abuse IP DB Check" , action="store_true")
parser.add_argument("-de", "--detailed", help="Toogle Detailed Analysis Check (Mainly for Virustotal)" , action="store_true")

args = parser.parse_args()

#####################################################################################################################################

# If Else Statements For Command Line Options #######################################################################################

# Those options simply gathers your apikey from above and make the http requests. Once they retrieve the json reponses, they pass them into the releaded objects to parsed and
# ready to be reported.

# IP ADDRESS CHCECK #################################################################################################################


if args.fileread is True:
	args.ipaddr = " "
	files = os.listdir("./Bulkoperations")
	ipaddr = []
	print("""Bulkoperations: This operation will help you to get reputation of ip's that inside of a file. 
Operation supports the csv and txt files. Txt files must only contains the IP addresses line-by-line. A headerless csv won't be readed. If you have multiple headers (like if you want to select a spessific column from a multi-columned .csv) you will be asked to provide. 
	""")
	for i,v in enumerate(files):
		print(i , v)
	selected = files[int(input("Selectfile(number):"))]
	fileextention = pathlib.Path("./Bulkoperations/" + selected).suffix
	if fileextention == ".txt":
		with open("./Bulkoperations/" + selected , "r") as r:
			lines = r.readlines()
			for i in lines:
				i.strip()
				ipaddr.append(i)
			for i in ipaddr:
				ip = i.strip()
				print(i)
				request = requests.get("https://api.xforce.ibmcloud.com/ipr/" + ip , auth=(authkeyexch, authpasswdexch) , headers = {'Accept': 'application/json'})
				whois = requests.get("https://api.xforce.ibmcloud.com/whois/" + ip ,  auth=(authkeyexch , authpasswdexch))
				report_data = json.loads(request.text)
				whois_data = json.loads(whois.text)
				result = reputationtool(ip, report_data, whois_data)
				result.IBMReputationExport()
			print("Operation Completed")
	if fileextention == ".csv":
		header = input("Header: ")
		if header == None:
			raise Exception("You must provide a header name. If it is empty, convert it to a text file and use it that way.")
		else:
			file = pd.read_csv("./Bulkoperations/" + selected)
			selectcolm = file[header]
			for i in selectcolm:
				ip = i
				request = requests.get("https://api.xforce.ibmcloud.com/ipr/" + ip , auth=(authkeyexch, authpasswdexch) , headers = {'Accept': 'application/json'})
				whois = requests.get("https://api.xforce.ibmcloud.com/whois/" + ip ,  auth=(authkeyexch , authpasswdexch))
				report_data = json.loads(request.text)
				whois_data = json.loads(whois.text)
				result = reputationtool(ip, report_data, whois_data)
				result.IBMReputationExport()

if args.ipaddr != None:
	if args.exchange is True:
		if args.export is True:
			allips_unlisted = args.ipaddr
			allips = allips_unlisted.split(',')
			for i in allips:
				ip = i
				request = requests.get("https://api.xforce.ibmcloud.com/ipr/" + ip , auth=(authkeyexch, authpasswdexch) , headers = {'Accept': 'application/json'})
				whois = requests.get("https://api.xforce.ibmcloud.com/whois/" + ip ,  auth=(authkeyexch , authpasswdexch))
				report_data = json.loads(request.text)
				whois_data = json.loads(whois.text)
				result = reputationtool(ip, report_data, whois_data)
				result.IBMReputationExport()


		else:
			allips_unlisted = args.ipaddr
			allips = allips_unlisted.split(',')
			for i in allips:
				ip = i
				request = requests.get("https://api.xforce.ibmcloud.com/ipr/" + ip , auth=(authkeyexch, authpasswdexch) , headers = {'Accept': 'application/json'})
				whois = requests.get("https://api.xforce.ibmcloud.com/whois/" + ip ,  auth=(authkeyexch , authpasswdexch))
				report_data = json.loads(request.text)
				whois_data = json.loads(whois.text)
				result = reputationtool(ip, report_data, whois_data)
				result.IBMIPReputation()

	else:
		pass
	if args.abuseipdb is True:
		allips_unlisted = args.ipaddr
		allips = allips_unlisted.split(',')
		for i in allips:
			abusemainurl = "https://api.abuseipdb.com/api/v2/check"
			age = int("100")
			querystring = {
    			'ipAddress': i,
    			'maxAgeInDays': age,
			"verbose": True
			}
			headers = {
    			'Accept': 'application/json',
    			'Key':  abuseapikey,
			}
			# verbose = "verbose"

			responseabuseip = requests.request(method='GET', url=abusemainurl, headers=headers, params=querystring)
			# print(responseabuseip)
			decodedResponse = json.loads(responseabuseip.text)
			abuseipdbresponse = json.dumps(decodedResponse, sort_keys=True, indent=4)
			# print(abuseipdbresponse)
			# print(type(decodedResponse))
			abuseresult = AbuseIPDB(decodedResponse, i)
			abuseresult.abuseipreputation()
	else:
		pass
	if args.virustotal is True:
		allips_unlisted = args.ipaddr
		allips = allips_unlisted.split(',')
		for i in allips:
				ip = i
				vtheaders = {
				'x-apikey':vtapikey
				}
				request = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}" , headers=vtheaders)
				ipresult = json.loads(request.text)
				vtresponse = json.dumps(ipresult , sort_keys=True , indent=4)
				#print(type(vtresponse))
				#print(vtresponse)
				parsedresult = vtipcheck(ipresult)
				parsedresult.virustotalipcheck()
	if args.detailed is True:
		allips_unlisted = args.ipaddr
		allips = allips_unlisted.split(',')
		for i in allips:
				ip = i
				vtheaders = {
				'x-apikey':vtapikey
				}
				request = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}" , headers=vtheaders)
				ipresult = json.loads(request.text)
				vtresponse = json.dumps(ipresult , sort_keys=True , indent=2)
				#print(type(vtresponse))
				#print(vtresponse)
				parsedresult = vtipcheck(ipresult)
				parsedresult.virustotalipdetailedcheck()


	else:
		pass
else:
	pass

#####################################################################################################################################

# URL CHCECK #################################################################################################################



if args.url != None:
	if args.exchange is True:
		allurls_unlisted = args.url
		allurls = allurls_unlisted.split(',')
		for m in allurls:
			url = m
			urlrequest = requests.get("https://api.xforce.ibmcloud.com/url/" + url , auth=(authkeyexch, authpasswdexch) , headers = {'Accept': 'application/json'})
			urlwhois = requests.get("https://api.xforce.ibmcloud.com/whois/" + url ,  auth=(authkeyexch , authpasswdexch))
			urlreport_data = json.loads(urlrequest.text)
			urlwhois_data = json.loads(urlwhois.text)
			#print(json.dumps(urlreport_data, indent=4))
			# print(json.dumps(urlwhois_data, indent=4))
			urlresult = xforceurlcheck(urlreport_data, urlwhois_data, url)
			urlresult.urlreporter()
	else:
		pass
	
	if args.virustotal is True:
			allurls_unlisted = args.url
			allurls = allurls_unlisted.split(',')
			for i in allurls:
				url = i
				vtheaders = {
					'x-apikey': vtapikey,
				}
				data = {
					'url': url
				}
				request = requests.post(f"https://www.virustotal.com/api/v3/urls", headers=vtheaders , data=data)
				urlresult = request.json()
				try:
					errcode = urlresult["error"]["code"]
				except:
					resultid = urlresult["data"]["id"]
					virustotalurlcheckadapter(resultid, vtheaders)		

#####################################################################################################################################

# FİLE HASH CHCECK #################################################################################################################

if args.filehash != None:
	if args.virustotal is True:
		allhash_unlisted = args.filehash
		allhashes = allhash_unlisted.split(',')
		for i in allhashes:
			hashval = i
			vtmain = "https://www.virustotal.com/api/v3/files/"
			vtheaders = {
				'x-apikey':vtapikey
			}
			vtmainrequest = requests.get(vtmain + hashval , headers=vtheaders)
			vtresult = json.loads(vtmainrequest.text)
			try:
				errcode = vtresult["error"]["code"]
				print("ERROR:" + " " + errcode)
				print("Check With:" + " " + "https://www.virustotal.com/gui/search/" + hashval)
				sys.exit(0)
			except KeyError:
				vtscanresult = virustotalhashcheck(vtresult, hashval)
				vtscanresult.virustotalhashchecker()
	if args.detailed is True:
		allhash_unlisted = args.filehash
		allhashes = allhash_unlisted.split(',')
		for i in allhashes:
			hashval = i
			vtmain = "https://www.virustotal.com/api/v3/files/"
			vtheaders = {
				'x-apikey':vtapikey
			}
			vtmainrequest = requests.get(vtmain + hashval , headers=vtheaders)
			vtresult = json.loads(vtmainrequest.text)
			try:
				errcode = vtresult["error"]["code"]
				print("ERROR:" + " " + errcode)
				print("Check With:" + " " + "https://www.virustotal.com/gui/search/" + hashval)
				sys.exit(0)
			except KeyError:
				vtscanresult = virustotalhashcheck(vtresult, hashval)
				#vtscanresult.virustotalhashchecker()
				vtscanresult.virustotalhashcheckerdetailed()
	else:
		pass
	if args.exchange is True:
		allhashibm_unlisted = args.filehash
		allhashesibm = allhashibm_unlisted.split(',')
		for i in allhashesibm:
			ibmhash = i
			hashrequest = requests.get("https://api.xforce.ibmcloud.com/malware/" + ibmhash , auth=(authkeyexch, authpasswdexch) , headers = {'Accept': 'application/json'})
			hashreportdata = json.loads(hashrequest.text)
			hashresult = ibmhashcheck(hashreportdata, ibmhash)
			hashresult.generatehashreport()
	else:
		pass
	if args.abuseipdb is True:
		print("This operation is not supported by abuseipdb. Please type -h to gather more information.")
		sys.exit(0)
