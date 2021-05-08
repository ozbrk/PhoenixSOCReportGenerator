import sys
class ibmhashcheck:
    def __init__(self, hashreportdata, ibmhash):
        self.hashreportdata = hashreportdata
        self.ibmhash = ibmhash

    def generatehashreport(self):
        # Debug Area#
        # print(self.hashreportdata)

        try:
            hash_name = self.ibmhash
        except EnvironmentError:
            raise
        try:
            firstcheck = str(self.hashreportdata["malware"])
        except KeyError:
            print(" ")
            print("[X-Force] Limited information is available. Use the contribution form or the comments option to share information about this observable, or add this report to a Collection.")
            print(" ")
            print("Information from X Force is not eligible. Please use another tool or conduct a manual search.")
            print(" ")
            sys.exit(0)
        try:
            hash_type = str(self.hashreportdata["malware"]["type"])
        except KeyError:
            raise
        try:
            sha256 = str(self.hashreportdata["malware"]["sha256"])
        except KeyError:
            sha256 = "N/A"
        try:
            risk_score = str(self.hashreportdata["risk"])
        except:
            risk_score = "N/A"
        try:
            report_source = str(self.hashreportdata["malware"]["origins"]["external"]["source"])
        except:
            report_source = "N/A"
        try:
            malware_type = str(self.hashreportdata["malware"]["origins"]["external"]["malwareType"])
        except:
            malware_type = "N/A"
        try:
            malware_platform = str(self.hashreportdata["malware"]["origins"]["external"]["platform"])
        except:
            malware_platform = "N/A"

        print(f"Risk Score:" + " " + risk_score)
        print(f"Hash Name:" + " " + hash_name)
        print(f"Hash Type:" + " " + hash_type)
        print(f"SHA256:" + " " + sha256)
        print(f"Report Source:" + " " + report_source)
        print(f"Malware Type:" + " " + malware_type)
        print(f"Malware Platform:" + " " + malware_platform)
