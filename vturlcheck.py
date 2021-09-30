import json
from os import lseek
from tabulate import tabulate
from rich.console import Console
from rich.table import Table

class virustotalurlcheck:

    def __init__(self, analysisresult):
        self.analysisresult = analysisresult
    
    def vturlcheck(self):
        console = Console()
        try:
            metdata = self.analysisresult["meta"]["url_info"]["url"]
            idtada = self.analysisresult["meta"]["url_info"]["id"]
            status = self.analysisresult["data"]["attributes"]["status"]
            harmless = str(self.analysisresult["data"]["attributes"]["stats"]["harmless"])
            malicious = str(self.analysisresult["data"]["attributes"]["stats"]["malicious"])
            suspicious = str(self.analysisresult["data"]["attributes"]["stats"]["suspicious"])
            undetected = str(self.analysisresult["data"]["attributes"]["stats"]["undetected"])
            timeout = str(self.analysisresult["data"]["attributes"]["stats"]["timeout"])
        except:
            raise
        indicatornames = []
        categories = []
        results = []
        methods = []
        engine_names = []
        for key in self.analysisresult["data"]["attributes"]["results"]:
            indicatornames.append(key)
            categories.append(self.analysisresult["data"]["attributes"]["results"][f"{key}"]["category"])
            results.append(self.analysisresult["data"]["attributes"]["results"][f"{key}"]["result"])
            methods.append(self.analysisresult["data"]["attributes"]["results"][f"{key}"]["method"])
            engine_names.append(self.analysisresult["data"]["attributes"]["results"][f"{key}"]["engine_name"])
        scanresults = zip(indicatornames , categories , results , methods , engine_names)
        main_result_table = Table(title="Main Results", show_header=False, show_lines=True)
        main_result_table.add_row("URL" , metdata)
        main_result_table.add_row("ID" , idtada)
        main_result_table.add_row("Status" , status)
        main_result_table.add_row("OVERALL ANALYSIS")
        main_result_table.add_row("Harmless" , harmless)
        main_result_table.add_row("Suspicious" , suspicious)
        main_result_table.add_row("Malicious" , malicious)
        main_result_table.add_row("Undetected" , undetected)
        main_result_table.add_row("Timeout" , timeout)
        console.print(main_result_table)
        for indicatorname , category , result , method , engine_name in scanresults:
            engine_table=Table(show_header=False, show_lines=True)
            engine_table.add_row("Engine" , indicatorname)
            engine_table.add_row("Category" , category)
            engine_table.add_row("Result" , result)
            engine_table.add_row("Method" , method)
<<<<<<< HEAD
            console.print(engine_table)
=======
            console.print(engine_table)
>>>>>>> 0514b373185f80d7e36b48c704edd4c2d33309f5
