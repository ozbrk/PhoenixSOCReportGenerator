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

        z = " "
        try:
            self.decodedResponse["data"]["reports"]
            z = 1
        except:
            z = 0

        if z == 1:
            allcomments=[]
            comments=[]
            countries=[]
            origincountries=[]
            reportdates=[]

            for i in self.decodedResponse["data"]["reports"]:
                allcomments.append(i)
            for x in allcomments:
                reportdate= x["reportedAt"]
                comment = x["comment"]
                country = x["reporterCountryCode"]
                origincountry = x["reporterCountryName"]
                comments.append(comment)
                countries.append(country)
                origincountries.append(origincountry)
                reportdates.append(reportdate)
            reportset = zip(comments , reportdates , countries , origincountries)
            print(" ")
            print(f"IP Report For" + " " + ip_string)
            print(f"Abuse IP DB Score:" + ip_confidence)
            print(f"ISP:" + " " + isp)
            print(f"Country:" + " " + country )
            print(" ")
            print(f"Commnets:")
            print(" ")
            for m , n , l , v in reportset:
                try:
                    print(f"Comment: " + m)
                except:
                    print("Comment: N/A")
                try:
                    print(f"Date: " + n)
                except:
                    print("Date: N/A")
                try:
                    print(f"Country: " + l)
                except:
                    print("Country: N/A")
                try:    
                    print(f"Reported From: " + v)
                except:    
                    print("Reported From: N/A")
            print(" ")
        else:
            print(" ")
            print(f"IP Report For" + " " + ip_string)
            print(f"Abuse IP DB Score:" + ip_confidence)
            print(f"ISP:" + " " + isp)
            print(f"Country:" + " " + country )
            print(" ")
            print(f"Commnets: No Comment Recieved!")
