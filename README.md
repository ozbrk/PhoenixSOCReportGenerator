# Phoneix Reporting Tool for SOC Analysts

Phoneix is a reporting tool mainly aiming for SOC analiysts to prepare quick reports for their customers.

## Installation

First step here - as very usual - cloning this script to your local machine by either using git clone or downloading it as a zip file. 
Scripts will require some dependicies (again as very usual) sadly I'm still learning the Git actions so you need to run the "dependencies.py" first.
After the dependencies are installed, you need three api keys. 

- IBM X-Force Exchange API (apikey and password)
- Abuseipdb API
- Virustotal Public API

authkeyexch is your IBM X Force Exchange API key
authpasswdexch is your IBM X Force Exchange API password.
vtapikey is your virustotal apikey.
abuseapikey is your abuseipdb apikey.

All of those keys can be obtained freely as they are all public api's. No commercial api functions are supported in this program. 

In the old edition you were need to pass the keys directly into the code but now Dependencies.py makes it for you. Just run the dependencies.py and follow the instructions.


## Usage

General syntax of the script is as follows:

```bash
usage: main.py [-h] [-f filehash] [-ip ip] [-u URL] [-ex] [-vt] [-ab]

optional arguments:
  -h, --help            show this help message and exit
  -f filehash, --filehash filehash
                        type desired file hash
  -ip ip, --ipaddr ip   type desired ip adress for check
  -u URL, --url URL     type desired url
  -ex, --exchange       Toogle IBM X-Force Exchange Check
  -vt, --virustotal     Toogle Virus Total Check
  -ab, --abuseipdb      Toogle Abuse IP DB Check
```

###Example usage:

```bash
ozberk@mainac:~/Projects/OOP/Source$ python3 main.py -i 213.74.26.138  -ex -ab
```


