# Phoenix Reporting Tool for SOC Analysts

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
usage: python3 Phoneix.py [-h] [-f filehash] [-ip ip] [-u URL] [-ex] [-vt] [-ab]

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

### Example Usage:

```bash
ozberk@mainac:~/Projects/OOP/Source$ python3 main.py -i 213.74.26.138  -ex -ab
```

### Example Output:

```bash
ozberk@ozberk-ABRA-A5-V6-2:~/PhoenixSOCReportGenerator$ python3 Phoneix.py -i 1.1.1.1 -ex -vt -ab
 
IP Reputation 1.1.1.1 :
Risk Score: Medium
Categorization: Malware , Botnet Command and Control Server 
Location: Australia
Registrant Organization: APNIC Research and Development
Registrar Name: ORG-ARAD1-AP
-----------------------------------------------------------------------------
Serach more with:
https://exchange.xforce.ibmcloud.com/ip/1.1.1.1
https://www.abuseipdb.com/check/1.1.1.1
https://www.virustotal.com/gui/ip-address/1.1.1.1/detection
-----------------------------------------------------------------------------
 
 
IP Report For 1.1.1.1
Abuse IP DB Score:0
ISP: APNIC and CloudFlare DNS Resolver Project
Country: DE
 
Commnets:
 
Comment: DNS Sucks
Date: 2021-08-19T20:12:49+00:00
Country:US
Reported From: United States of America
 
Comment: Aug 17 08:00:02 polybag kernel: [60288.113552] PORT DENIED: IN=ens3 OUT= MAC=02:00:17:01:2a:c7:00:00:17:54:56:91:08:00 SRC=1.1.1.1 DST=10.0.0.69 LEN=52 TOS=0x00 PREC=0x00 TTL=59 ID=0 DF PROTO=TCP SPT=853 DPT=39828 SEQ=2671781897 ACK=3614523825 WINDOW=65535 RES=0x00 ACK SYN URGP=0 OPT (020405B4010104020103030A) 
Aug 17 08:00:02 polybag kernel: [60288.114997] PORT DENIED: IN=ens3 OUT= MAC=02:00:17:01:2a:c7:00:00:17:54:56:91:08:00 SRC=1.1.1.1 DST=10.0.0.69 LEN=40 TOS=0x00 PREC=0x00 TTL=59 ID=65401 DF PROTO=TCP SPT=853 DPT=39828 SEQ=2671781898 ACK=3614524048 WINDOW=66 RES=0x00 ACK URGP=0
Date: 2021-08-17T00:14:39+00:00
Country:KR
Reported From: Korea (Republic of)
 
Comment: Fail2Ban Auto Report - VPN Hacking Attempt
Date: 2021-08-13T14:29:37+00:00
Country:GB
Reported From: United Kingdom of Great Britain and Northern Ireland
 
Comment: Fail2Ban Auto Report - VPN Hacking Attempt
Date: 2021-08-05T20:04:27+00:00
Country:GB
Reported From: United Kingdom of Great Britain and Northern Ireland
 
Comment: Port Scan
...
Date: 2021-07-31T12:15:46+00:00
Country:TH
Reported From: Thailand
 
Comment: HTTP/80/443/8080 Probe, Hack -
Date: 2021-07-05T05:07:04+00:00
Country:RS
Reported From: Serbia
 
Comment: Scanning random ports - tries to find possible vulnerable services
Date: 2021-07-01T20:20:42+00:00
Country:FI
Reported From: Finland
 
Comment: Unauthorized Access Attempt: TCP Port 80
Date: 2021-07-01T07:52:43+00:00
Country:CA
Reported From: Canada
 
Comment: PortscanT
Date: 2021-06-30T22:27:29+00:00
Country:DE
Reported From: Germany
 
Comment: PortscanM
Date: 2021-06-30T21:16:49+00:00
Country:DE
Reported From: Germany
 
Comment: MultiHost/MultiPort Probe, Scan, Hack -
Date: 2021-06-30T20:26:20+00:00
Country:RS
Reported From: Serbia
 
Comment: PortscanT
Date: 2021-06-29T20:30:31+00:00
Country:DE
Reported From: Germany
 
Comment: hacking
Date: 2021-06-28T18:03:51+00:00
Country:US
Reported From: United States of America
 
Comment: hacks
Date: 2021-06-28T18:02:54+00:00
Country:NL
Reported From: Netherlands
 
Comment: Tried our host z.
Date: 2021-06-19T07:07:23+00:00
Country:PL
Reported From: Poland
 
Comment: SSH login attempts with user root.
Date: 2021-06-16T06:28:54+00:00
Country:IN
Reported From: India
 
Comment: Come a playing Minecraft IP: play.rodion-network.com
Date: 2021-06-15T15:49:49+00:00
Country:AR
Reported From: Argentina
 
Comment: Hacker vpn
Date: 2021-06-10T15:56:04+00:00
Country:GB
Reported From: United Kingdom of Great Britain and Northern Ireland
 
Comment: hackers use this
Date: 2021-06-09T18:58:45+00:00
Country:GB
Reported From: United Kingdom of Great Britain and Northern Ireland
 
Comment: 1.1.1.1 port 8 --> IPS Prevention Alert: ICMP Echo Reply
Date: 2021-06-07T17:55:24+00:00
Country:US
Reported From: United States of America
 
Comment: This is a test...
Date: 2021-06-02T20:30:00+00:00
Country:PK
Reported From: Pakistan
 
Comment: https://youtu.be/8ybW48rKBME
Date: 2021-06-01T19:22:21+00:00
Country:PL
Reported From: Poland
 
Comment: Hinack nya acc Ng boyfriend ko
Date: 2021-05-30T14:18:56+00:00
Country:PH
Reported From: Philippines
 
Comment: $f2bV_matches
Date: 2021-05-29T23:05:56+00:00
Country:ES
Reported From: Spain
 
Comment: vpn that hackers on on
Date: 2021-05-29T22:24:57+00:00
Country:US
Reported From: United States of America
 
Comment: 27-May-2021 15:53:27.567 client @0x7ffb42e60c00 1.1.1.1#6286 (.): query (cache) './ANY/IN' denied
Date: 2021-05-27T20:53:28+00:00
Country:US
Reported From: United States of America
 
Comment: Test
Date: 2021-05-26T14:04:31+00:00
Country:NL
Reported From: Netherlands
 
Comment: Listed on hostkarma.junkemailfilter.com whilelist - trusted nonspam   / proto=6  .  srcport=80  .  dstport=46567  .      (2560)
Date: 2021-05-21T19:33:55+00:00
Country:GB
Reported From: United Kingdom of Great Britain and Northern Ireland
 
Comment: ip
Date: 2021-05-20T07:48:42+00:00
Country:US
Reported From: United States of America
 
Comment: test
Date: 2021-05-19T07:49:01+00:00
Country:US
Reported From: United States of America
 
Comment: 2021-05-18T06:42:58.552588+0300
ET SCAN Potential SSH Scan
Date: 2021-05-18T21:11:31+00:00
Country:BY
Reported From: Belarus
 
Comment: Port scan of TCP port 22
Date: 2021-05-18T17:52:14+00:00
Country:US
Reported From: United States of America
 
Comment: [H1.VM10] Blocked by UFW
Date: 2021-05-18T11:49:21+00:00
Country:DE
Reported From: Germany
 
Comment: TCP ports : 22 / 23
Date: 2021-05-18T10:12:48+00:00
Country:FR
Reported From: France
 
Comment: [H1.VM2] Blocked by UFW
Date: 2021-05-18T07:56:08+00:00
Country:DE
Reported From: Germany
 
Comment: Unauthorised access (May 18) SRC=1.1.1.1 LEN=64 TTL=111 ID=52131 DF TCP DPT=23 WINDOW=65535 SYN
Date: 2021-05-18T05:25:36+00:00
Country:LT
Reported From: Lithuania
 
Comment: 
Date: 2021-05-18T05:24:02+00:00
Country:CZ
Reported From: Czechia
 
Comment: SSH intrusion attempt from one.one.one.one port 4053
Date: 2021-05-18T04:50:01+00:00
Country:DE
Reported From: Germany
 
Comment: May 18 06:26:11  [2217092.906358] [UFW BLOCK]  OUT= MAC=00:01:e8:d8:95:35:08:00 SRC=1.1.1.1 DST=IP hidden LEN=64 TOS=0x00 PREC=0x00 TTL=99 ID=32030 DF PROTO=TCP SPT=6752 DPT=23 WINDOW=64240 RES=0x00 SYN URGP=0 
May 18 06:26:11  [2217092.906883] [UFW BLOCK]  OUT= MAC=00:01:e8:d8:94:d8:08:00 SRC=1.1.1.1 DST=IP hidden LEN=64 TOS=0x00 PREC=0x00 TTL=101 ID=39842 DF PROTO=TCP SPT=64822 DPT=23 WINDOW=64240 RES=0x00 SYN URGP=0 
May 18 06:
...
Date: 2021-05-18T04:26:34+00:00
Country:CZ
Reported From: Czechia
 
Comment: 
Date: 2021-05-18T03:44:33+00:00
Country:NL
Reported From: Netherlands
 
Comment: Telnet Server BruteForce Attack
Date: 2021-05-18T02:26:41+00:00
Country:GR
Reported From: Greece
 
Comment: 8080/tcp 23/tcp 22/tcp
[2021-05-17]3pkt
Date: 2021-05-17T23:40:05+00:00
Country:JP
Reported From: Japan
 
Comment: Port scan on 3 port(s): 22 23 8080
Date: 2021-05-17T21:21:19+00:00
Country:FR
Reported From: France
 
Comment: [New] Noxious/Nuisible/вредоносный Host.
Date: 2021-05-17T20:51:22+00:00
Country:FR
Reported From: France
 
Comment: 2021-05-17T19:35:04.327Z Portscan drop, PROTO=TCP SPT=49378 DPT=23
2021-05-17T19:35:03.688Z Portscan drop, PROTO=TCP SPT=22917 DPT=23
Date: 2021-05-17T19:35:06+00:00
Country:CA
Reported From: Canada
 
Comment: Automatic report - Port Scan Attack
Date: 2021-05-17T11:38:33+00:00
Country:FR
Reported From: France
 
Comment: [H1.VM1] Blocked by UFW
Date: 2021-05-17T11:37:09+00:00
Country:DE
Reported From: Germany
 
 
 
MAIN REPORT
-----------------------------------------------
Regional Internet Registry: APNIC
Jarm: 27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c
Network: 1.1.1.0/24
Counrty: AU
Owner: CLOUDFLARENET
Virus Total Reputation Score: 44
 
OVERALL ANALYSİS REPORT
-----------------------------------------------
Harmless: 74
Malicious: 1
Suspicious: 1
Undetected: 10
Timeout: 0
-----------------------------------------------
 
WHOIS DATA:
-----------------------------------------------
Domain Name: one.one
Registry Domain ID: DB8D9612E99A84235AF9133FBE4EB27D5-ARI
Registrar WHOIS Server:
Registrar URL:
Updated Date: 2021-07-04T12:15:49Z
Creation Date: 2015-05-20T12:15:44Z
Registry Expiry Date: 2022-05-20T12:15:44Z
Registrar: One.com A/S - ONE
Registrar IANA ID: 9998
Registrar Abuse Contact Email:
Registrar Abuse Contact Phone:
Domain Status: ok https://icann.org/epp#ok
Registry Registrant ID: REDACTED FOR PRIVACY
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: One.com A/S
Registrant Street: REDACTED FOR PRIVACY
Registrant Street: REDACTED FOR PRIVACY
Registrant Street: REDACTED FOR PRIVACY
Registrant City: REDACTED FOR PRIVACY
Registrant State/Province:
Registrant Postal Code: REDACTED FOR PRIVACY
Registrant Country: dk
Registrant Phone: REDACTED FOR PRIVACY
Registrant Phone Ext: REDACTED FOR PRIVACY
Registrant Fax: REDACTED FOR PRIVACY
Registrant Fax Ext: REDACTED FOR PRIVACY
Registrant Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Registry Admin ID: REDACTED FOR PRIVACY
Admin Name: REDACTED FOR PRIVACY
Admin Organization: REDACTED FOR PRIVACY
Admin Street: REDACTED FOR PRIVACY
Admin Street: REDACTED FOR PRIVACY
Admin Street: REDACTED FOR PRIVACY
Admin City: REDACTED FOR PRIVACY
Admin State/Province: REDACTED FOR PRIVACY
Admin Postal Code: REDACTED FOR PRIVACY
Admin Country: REDACTED FOR PRIVACY
Admin Phone: REDACTED FOR PRIVACY
Admin Phone Ext: REDACTED FOR PRIVACY
Admin Fax: REDACTED FOR PRIVACY
Admin Fax Ext: REDACTED FOR PRIVACY
Admin Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Registry Tech ID: REDACTED FOR PRIVACY
Tech Name: REDACTED FOR PRIVACY
Tech Organization: REDACTED FOR PRIVACY
Tech Street: REDACTED FOR PRIVACY
Tech Street: REDACTED FOR PRIVACY
Tech Street: REDACTED FOR PRIVACY
Tech City: REDACTED FOR PRIVACY
Tech State/Province: REDACTED FOR PRIVACY
Tech Postal Code: REDACTED FOR PRIVACY
Tech Country: REDACTED FOR PRIVACY
Tech Phone: REDACTED FOR PRIVACY
Tech Phone Ext: REDACTED FOR PRIVACY
Tech Fax: REDACTED FOR PRIVACY
Tech Fax Ext: REDACTED FOR PRIVACY
Tech Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Name Server: a.b-one-dns.net
Name Server: b.b-one-dns.net
DNSSEC: signedDelegation
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2021-08-14T15:00:55Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

The Service is provided so that you may look up certain information in relation to domain names that we store in our database.

Use of the Service is subject to our policies, in particular you should familiarise yourself with our Acceptable Use Policy and our Privacy Policy.

The information provided by this Service is 'as is' and we make no guarantee of it its accuracy.

You agree that by your use of the Service you will not use the information provided by us in a way which is:
* inconsistent with any applicable laws,
* inconsistent with any policy issued by us,
* to generate, distribute, or facilitate unsolicited mass email, promotions, advertisings or other solicitations, or
* to enable high volume, automated, electronic processes that apply to the Service.

You acknowledge that:
* a response from the Service that a domain name is 'available', does not guarantee that is able to be registered,
* we may restrict, suspend or terminate your access to the Service at any time, and
* the copying, compilation, repackaging, dissemination or other use of the information provided by the Service is not permitted, without our express written consent.

This information has been prepared and published in order to represent administrative and technical management of the TLD.

We may discontinue or amend any part or the whole of these Terms of Service from time to time at our absolute discretion.

-----------------------------------------------

```


