from ipaddress import ip_address
   
def IPAddress(IP: str) -> str:
    return "Private" if (ip_address(IP).is_private) else "Public"
     
if __name__ == '__main__' : 
    
    ip = input("ip:")

    print(IPAddress(ip))  