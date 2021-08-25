import re

class reputationtool:

    def __init__(self, ip, report_data, whois_data):
        self.ip = ip
        self. report_data = report_data
        self. whois_data = whois_data
        # json = __import__('json')


    def IBMIPReputation(self):

        try:
            ip_name = str(self.report_data["ip"])
        except: 
            ip_name = "N/A"
        try:
            risk_score = float(self.report_data["score"])
        except:
            risk_score = str("unknown please wisit the provided website")
        if risk_score < 2.0:
            risk_score_string = "Low"
        elif 2.0 < risk_score < 6.0:
            risk_score_string = "Medium"
        elif 6.0 < risk_score:
            risk_score_string = "High"    
        try:
            categorization_raw = str(self.report_data["cats"])
        except:
            categorization_raw = "N/A"
        if categorization_raw == 'N/A':
            categorization_ok = "N/A"
        elif categorization_raw == "{}":
            categorization_ok = "Unsuspicious"
        else:
            categorization_pre = categorization_raw.translate(str.maketrans(' ', ' ' , '1234567890'))
            categorization_ok = categorization_pre.replace("{}',':" , " ")
        try:
            location = str(self.report_data["geo"]["country"])
        except:
            location = "N/A"
        try:
            registrantorg = self.whois_data["contact"][0]["organization"]
        except:
            registrantorg = "N/A"
        try:
            registrarname = str(self.whois_data["registrarName"])
        except:
             registrarname = "N/A"

        print(" ")
        print(f"IP Reputation" + " " + ip_name + " " + ":")
        print(f"Risk Score:" + " " + risk_score_string)
        print(f"Categorization:" + " " + re.sub('[^a-z \|\| A-Z \|\| \, \|\| \s+]' , '' , categorization_ok))
        print(f"Location:" + " " + location)
        print(f"Registrant Organization:" + " " + str(registrantorg))
        print(f"Registrar Name:" + " " + registrarname)
        print("-----------------------------------------------------------------------------")
        print("Serach more with:")
        print(f"https://exchange.xforce.ibmcloud.com/ip/" + self.ip)
        print(f"https://www.abuseipdb.com/check/" + self.ip)
        print(f"https://www.virustotal.com/gui/ip-address/" + self.ip + "/detection")
        print("-----------------------------------------------------------------------------")
        print(" ")


    def IBMReputationExport(self):

        try:
            ip_name = str(self.report_data["ip"])
        except: 
            ip_name = "N/A"
        try:
            risk_score = float(self.report_data["score"])
        except:
            risk_score = str("unknown please wisit the provided website")
        if risk_score < 2.0:
            risk_score_string = "Low"
        elif 2.0 < risk_score < 6.0:
            risk_score_string = "Medium"
        elif 6.0 < risk_score:
            risk_score_string = "High"    
        try:
            categorization_raw = str(self.report_data["cats"])
        except:
            categorization_raw = "N/A"
        if categorization_raw == 'N/A':
            categorization_ok = "N/A"
        elif categorization_raw == "{}":
            categorization_ok = "Unsuspicious"
        else:
            categorization_pre = categorization_raw.translate(str.maketrans(' ', ' ' , '1234567890'))
            categorization_ok = categorization_pre.replace("{}',':" , " ")
        try:
            location = str(self.report_data["geo"]["country"])
        except:
            location = "N/A"
        try:
            registrantorg = self.whois_data["contact"][0]["organization"]
        except:
            registrantorg = "N/A"
        try:
            registrarname = str(self.whois_data["registrarName"])
        except:
             registrarname = "N/A"

        print("-----------------------------------------------------------------------------")
        print(f"IP Reputation" + " " + ip_name + " " + ":")
        print(f"Risk Score:" + " " + risk_score_string)
        print(f"Categorization:" + " " + re.sub('[^a-z \|\| A-Z \|\| \, \|\| \s+]' , '' , categorization_ok))
        print(f"Location:" + " " + location)
        print(f"Registrant Organization:" + " " + str(registrantorg))
        print(f"Registrar Name:" + " " + registrarname)
        print("-----------------------------------------------------------------------------")







