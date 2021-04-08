from termcolor import colored
class virustotalhashcheck:

    def __init__(self, vtresult, hashval):
        self.vtresult = vtresult
        self.hashval = hashval

    def virustotalhashchecker(self):
        antivirs = open("vtlist.txt", "r")
        antivirlist_list = antivirs.readlines()
        for i in antivirlist_list:
            f = i.strip("\n")
            try:
                z = self.vtresult["data"]["attributes"]["last_analysis_results"][f]
            except:
                pass
            try:
                engine_name = z["engine_name"]
            except KeyError:
                raise
            try:
                engine_result = z["result"]
            except KeyError:
                raise
            try:
                engine_categorization = str(z["category"])
            except KeyError:
                raise
            if engine_name is None:
                engine_name = "N/A"
            else:
                pass
            if engine_result is None:
                engine_result = "N/A"
            else:
                pass
            if engine_categorization is None:
                engine_categorization = "N/A"
            else:
                pass

            print("-------------------")
            print(f"Engine Name:" + " " + engine_name)
            print(f"Result:" + " " + engine_result)
            if engine_categorization == "malicious":
                print(f"Category" + " " + engine_categorization)
                print(colored('Attention' , 'red'))
            elif engine_categorization == "type-unsupported":
                print(f"Category" + " " + engine_categorization)
                print(colored('Not Supported!' , 'yellow'))
            else:
                print(f"Category" + " " + engine_categorization)

            print("-------------------")
            print(" ")

