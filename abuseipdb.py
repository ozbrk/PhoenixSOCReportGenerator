from importlib import import_module

class AbuseIPDB:

    def __init__(self, decodedResponse, ip):
       #json = __import__('json')
       self.decodedResponse = decodedResponse
       self.ip = ip

    def abuseipreputation(self):
        try:
            ip_string = str(self.decodedResponse["data"]["ipAddress"])
        except:
            ip_string = "None!"
        try:
            ip_confidence = str(self.decodedResponse["data"]["abuseConfidenceScore"])
        except:
            ip_confidence = "Error, check the website."
        try:
            isp = str(self.decodedResponse["data"]["isp"])
        except KeyError:
            isp = "Not Found"
        try:
            country = str(self.decodedResponse["data"]["countryCode"])
        except KeyError:
            country = "N/A"
        
        print(f"IP Report For" + " " + ip_string)
        print(f"Abuse IP DB Score:" + ip_confidence)
        print(f"ISP:" + " " + isp)
        print(f"Country:" + " " + country )
        print("Reports: Reports cannot be provided by the current version of this script please visit the following url https://www.abuseipdb.com/check/" + self.ip )
        #print(c)