from termcolor import colored
import json
from tabulate import tabulate

class vtipcheck:

    def __init__(self , ipresult):
        self.ipresult = ipresult
    
    def virustotalipcheck(self):
        try:
            registry = self.ipresult["data"]["attributes"]["regional_internet_registry"]
        except KeyError:
            registry = "N/A"
        try:
            jarm = str(self.ipresult["data"]["attributes"]["jarm"])
        except KeyError:
            jarm = "N/A"    
        try:
            subnetmask = str(self.ipresult["data"]["attributes"]["network"])
        except KeyError:
            subnetmask = "N/A"
        try:
            nation = str(self.ipresult["data"]["attributes"]["country"])
        except KeyError:
            nation = "N/A"
        try:
            owner = str(self.ipresult["data"]["attributes"]["as_owner"])
        except KeyError: 
            owner = "N/A"
        try:
            hrmlss = str(self.ipresult["data"]["attributes"]["last_analysis_stats"]["harmless"])
        except KeyError:
            hrmlss = "0"
        try:
            mal = str(self.ipresult["data"]["attributes"]["last_analysis_stats"]["malicious"])
        except KeyError:
            mal = "0"
        try:
            suspicious = str(self.ipresult["data"]["attributes"]["last_analysis_stats"]["suspicious"])
        except KeyError:
            suspicious = "0"
        try:
            undetected = str(self.ipresult["data"]["attributes"]["last_analysis_stats"]["undetected"])
        except KeyError:
            undetected = "0"
        try:
            timeout = str(self.ipresult["data"]["attributes"]["last_analysis_stats"]["timeout"])
        except KeyError: 
            timeout = "0"
        try:
            reputation = str(self.ipresult["data"]["attributes"]["reputation"])
        except KeyError:
            reputation = "N/A"
        try:
            whois = str(self.ipresult["data"]["attributes"]["whois"])
        except KeyError:
            whois = "No Data"

        print(" ")
        print("MAIN REPORT")
        print("-----------------------------------------------")
        print(f"Regional Internet Registry:" + " " + registry)
        print(f"Jarm:" + " " + jarm)
        print(f"Network:" + " " + subnetmask)
        print(f"Counrty:" + " " + nation)
        print(f"Owner:" + " " + owner)
        print(f"Virus Total Reputation Score:" + " " + reputation)
        print(" ")
        print("OVERALL ANALYSİS REPORT") 
        print("-----------------------------------------------")       
        print(f"Harmless:" + " " + hrmlss)
        print(f"Malicious:" + " " + mal)
        print(f"Suspicious:" + " " + suspicious)
        print(f"Undetected:" + " " + undetected)
        print(f"Timeout:" + " " + timeout)
        print("-----------------------------------------------")
        print(" ")
        print(f"WHOIS DATA:")
        print("-----------------------------------------------")
        print(whois)
        print("-----------------------------------------------")
        print(" ")

    def virustotalipdetailedcheck(self):

        print("ENGINE RESULTS:")   
        engine_names = []
        results = []
        engine_categorizations = []
        for value in self.ipresult["data"]["attributes"]["last_analysis_results"]:
            engine_names.append(value)
        for engine_name in engine_names:
            result = str(self.ipresult["data"]["attributes"]["last_analysis_results"][engine_name]["result"])
            engine_categorization = str(self.ipresult["data"]["attributes"]["last_analysis_results"][engine_name]["category"])
            engine_categorizations.append(engine_categorization)
            results.append(result)

        resulttable = zip(engine_names,results,engine_categorizations)
        headers = ["Engine Name" , "Result" , "Categorization"]

        print(tabulate(resulttable, headers=headers , tablefmt="grid"))

    def virustotalipcomments(self):
        com = 2 #placeholder. This part of the code is underconstruction 

