import json
from tabulate import tabulate
from rich.console import Console
from rich.table import Table

class virustotalhashcheck:

    def __init__(self, vtresult, hashval):
        self.vtresult = vtresult
        self.hashval = hashval

    def virustotalhashchecker(self):

        file_types = []
        probabilities = []

        try:
            description = self.vtresult["data"]["attributes"]["type_description"]
        except KeyError:
            description = "N/A"
        try:
            vhash = self.vtresult["data"]["attributes"]["vhash"]
        except KeyError:
            vhash = "N/A"
        try:
            file_names = []
            for value in self.vtresult["data"]["attributes"]["names"]:
                file_names.append(value)
            for file_name in file_names:
                file_name = file_name
        except KeyError:
            file_name="N/A"
        
        try:
            meaningfulname = self.vtresult["data"]["attributes"]["meaningful_name"]
        except KeyError:
            meaningfulname = "N/A"


        try:
            engine_names = []
            results = []
            engine_categorizations = []
            for value in self.vtresult["data"]["attributes"]["last_analysis_results"]:
                engine_names.append(value)
            for engine_name in engine_names:
                result = str(self.vtresult["data"]["attributes"]["last_analysis_results"][engine_name]["result"])
                engine_categorization = str(self.vtresult["data"]["attributes"]["last_analysis_results"][engine_name]["category"])
                engine_categorizations.append(engine_categorization)
                results.append(result)

            enginetable = Table(title="Engine Check Results")
            resulttable = zip(engine_names,results,engine_categorizations)
            headers = ["Engine Name" , "Result" , "Categorization"]
            for i in headers:
                enginetable.add_column(i)
            for engine_name , result , categorization in resulttable:
                enginetable.add_row(" " , " " , " ")
                enginetable.add_row(engine_name , result , categorization)
        except KeyError:
            print("No Engine Result Avalaible")

        try:
            hrmlss = str(self.vtresult["data"]["attributes"]["last_analysis_stats"]["harmless"])
        except:
            hrmlss = "0"
        try:
            mal = str(self.vtresult["data"]["attributes"]["last_analysis_stats"]["malicious"])
        except:
            mal = "0"
        try:
            suspicious = str(self.vtresult["data"]["attributes"]["last_analysis_stats"]["suspicious"])
        except:
            suspicious = "0"
        try:
            undetected = str(self.vtresult["data"]["attributes"]["last_analysis_stats"]["undetected"])
        except:
            undetected = "0"
        try:
            timeout = str(self.vtresult["data"]["attributes"]["last_analysis_stats"]["timeout"])
        except:
            timeout = "0"

        print("Main Report:")
        print("------------------------")
        print(f"Description:" + " " + description)
        print(f"VHash:" + " " + vhash)
        print(f"File Name:" + " " + file_name)
        print(f"Concluded Name:" + " " + meaningfulname)
        print(" ")
        print("OVERALL ANALYSIS STATS:")
        print("------------------------")
        print(f"Harmless:" + " " + hrmlss)
        print(f"Malicious:" + " " + mal)
        print(f"Suspicious:" + " " + suspicious)
        print(f"Undetected:" + " " + undetected)
        print(f"Timeout:" + " " + timeout)
        print("------------------------")
        print("------------------------")
        console = Console()
        console.print(enginetable)
        print("------------------------")
        
        
    def virustotalhashcheckerdetailed(self):
        
        try:
            x509data_names = []
            x509data_algorithms= []
            x509data_valid_from_data = []
            x509data_valid_to_data = []
            x509data_serial_numbers = []
            x509data_cert_issuers = []
            x509data_thumbprints = []
            x509data_valid_usages = []
            for x509data in self.vtresult["data"]["attributes"]["signature_info"]["x509"]:
                x509data_names.append(x509data["name"])
                x509data_algorithms.append(x509data["algorithm"])
                x509data_valid_from_data.append(x509data["valid from"])
                x509data_valid_to_data.append(x509data["valid to"])
                x509data_serial_numbers.append(x509data["serial number"])
                x509data_cert_issuers.append(x509data["cert issuer"])
                x509data_thumbprints.append(x509data["thumbprint"])
                x509data_valid_usages.append(x509data["valid_usage"])

            resulttable = zip(x509data_names,x509data_algorithms,x509data_valid_from_data,x509data_valid_to_data,x509data_serial_numbers,x509data_cert_issuers,x509data_thumbprints,x509data_valid_usages)
            headers = ["Name" , "Algorithm" , "Valid From" , "Valid To" , "Serial Number" , "Certification Issuer" , "Thumbprint" , "Valid Usage"]
            table = Table(title="X509 Results")
            for i in headers:
                table.add_column(i)
            for x509data_name , x509data_algorithm , x509data_valid_from , x509data_valid_to , x509data_serial_number , x509data_cert_issuer , x509data_thumbprint , x509data_valid_usage in resulttable:
                table.add_row(" " , " " , " " , " ")
                table.add_row(x509data_name , x509data_algorithm , x509data_valid_from , x509data_valid_to , x509data_serial_number , x509data_cert_issuer , x509data_thumbprint , x509data_valid_usage)
            console = Console()
            console.print(table)
        
        except KeyError:

            x509data = "No X509 Data"


