class xforceurlcheck:
    
    def __init__ (self, urlreport_data, urlwhois_data, url):
        self.urlwhois_data = urlwhois_data
        self.urlreport_data = urlreport_data
        self.url = url
    
    def urlreporter(self):

        """  DEBUG AREA

        print(self.urlreport_data)
        print("---------------------------------")
        print(self.urlwhois_data)
        print("----------------------------------")
        print("----------------------------------")
        print("----------------------------------")

        """

        try:
            url_name = str(self.urlreport_data["result"]["url"])
        except KeyError:
            url_name = "N/A"
        
        try: 
            url_category = str(self.urlreport_data["result"]["cats"])
        except KeyError:
            url_category = "N/A"
        
        url_category_raw = url_category.strip("{}':")
        url_category_final = url_category_raw.replace("': True" , " ")
        
        try:
            url_registrar_name = str(self.urlwhois_data["registrarName"])
        except KeyError:
            url_registrar_name = "N/A"
        
        try:
            url_registrant_org = str(self.urlwhois_data["contact"][0]["organization"])
        except KeyError:
            raise
        
        try:
            url_risk_score = float(self.urlreport_data["result"]["score"])
        except KeyError:
            raise

        if url_risk_score < 4.0:
            url_risk_score_str = "Low"
        elif 4.0 <= url_risk_score < 7.0: 
            url_risk_score_str = "Medium"
        elif 7.0 < url_risk_score:
            url_risk_score_str = "High"
        else:
            url_risk_score_str = "N/A"
        
        print(" ")
        print(f"Url Report for" + " " + url_name)
        print(f"Url Risk Score:" + " " + url_risk_score_str)
        print(f"Url Categorization:" + " " + url_category_final)
        print(f"Url Registrar Name:" + " " + str(url_registrar_name))
        print(f"Url Registrant Organization:" + " " + url_registrant_org)
        print("See full results on:" + " " + " " + "https://exchange.xforce.ibmcloud.com/url/" + self.url)
        