## File Analysis Tool --- OZBERK AKBAS
## 02.04.2020
## The program intended to analyze the given IP adress, hash value, file or file name given by user with IBM X-Force Exchange, Virus Total and Abuse IP DB
## The results will printed out as a report when everything is done and finished.

# IMPORTS ##########################################################################################################################

import sys
import argparse
import requests
import json
sys.path.append(".")
from ibmip import reputationtool
from abuseipdb import AbuseIPDB
from ibmurl import xforceurlcheck
from vthashcheck import virustotalhashcheck
from ibmhashcheck import ibmhashcheck

#####################################################################################################################################

# PUT YOUR APIKEYS HERE! ############################################################################################################

""" IBM API KEY AND PASSWD """

authkeyexch = "2b01e212-c2be-4e88-9863-35cf3eb34d16"
authpasswdexch = "7dac9f4e-9f50-4389-87c2-8cebc96a14bb"

# Go IBM X For Exchange and retrive your api key and password from https://exchange.xforce.ibmcloud.com/settings/api 

""" VITOTAL APIKEY AND PASSWD """

vtapikey = "6af5c7eed898ef035310059ae65cf09aba83eb68a40fd949fd0d3f67fd3ed0e8"

# Go Virustotal and register for your free apikey. Retrive it from https://www.virustotal.com/gui/user/<yourusername>/apikey

""" ABUSEIPDB APIKEY """

abuseapikey = "273e9adf7fc4efd7b4a56b4f2cf7ffbf526f95fd5109cc66955bd0fe3beca800f4cb0c235d0d828a"

# Go AbuseipDB and retrieve your freeapikey from https://www.abuseipdb.com/account/api#   

#####################################################################################################################################

# Command Line Parser ###############################################################################################################


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--filehash" , metavar = 'filehash' , type=str, help="type desired file hash")
parser.add_argument("-ip", "--ipaddr", metavar='ip' , help="type desired ip adress for check")
parser.add_argument("-u", "--url", help="type desired url")
parser.add_argument("-ex", "--exchange", help="Toogle IBM X-Force Exchange Check" , action="store_true")
parser.add_argument("-vt", "--virustotal", help="Toogle Virus Total Check" , action="store_true")
parser.add_argument("-ab", "--abuseipdb", help="Toogle Abuse IP DB Check" , action="store_true")
args = parser.parse_args()

#####################################################################################################################################

# If Else Statements For Command Line Options #######################################################################################

# Those options simply gathers your apikey from above and make the http requests. Once they retrieve the json reponses, they pass them into the releaded objects to parsed and 
# ready to be reported.

if args.ipaddr != None:
	if args.exchange is True:
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
			age = int("180")
			querystring = {
    		'ipAddress': i,
    		'maxAgeInDays': age,
			}
			headers = {
    		'Accept': 'application/json',
    		'Key':  abuseapikey
			}
			responseabuseip = requests.request(method='GET', url=abusemainurl, headers=headers, params=querystring)
			decodedResponse = json.loads(responseabuseip.text)
			abuseipdbresponse = json.dumps(decodedResponse, sort_keys=True, indent=4)
			# print(decodedResponse)
			# print(type(decodedResponse))
			abuseresult = AbuseIPDB(decodedResponse, i)
			abuseresult.abuseipreputation()
			
	else:
		pass
	if args.virustotal is True:
		print("Virustotal IP Check is not supported yet. Please check wtih X Force and click the provided link.")
		sys.exit(0)
	else:
		pass
else:
	pass


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
