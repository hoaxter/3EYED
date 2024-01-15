import whois
import shodan
import dns.resolver 
import requests  
import argparse  
import socket
from colorama import init, Fore


init()
red = Fore.RED
green = Fore.GREEN
blue = Fore.LIGHTBLUE_EX
yellow = Fore.YELLOW


arg = argparse.ArgumentParser(
    description="Basic Information Gathering Tool",
    usage="python ninfo.py -d example.com [-s IP]",
)
arg.add_argument("-d", "--domain",help="Enter the domain name for footprinting.") 
arg.add_argument("-s", "--shodan", help="Enter the ip for shodan search.")
arg.add_argument("-o", "--output", help="Enter the filename to write output.")

args = arg.parse_args()
domain = args.domain
ip = args.shodan
output = args.output

print( f'''{red}

██████╗ ███████╗██╗   ██╗███████╗██████╗ 
╚════██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗
 █████╔╝█████╗   ╚████╔╝ █████╗  ██║  ██║
 ╚═══██╗██╔══╝    ╚██╔╝  ██╔══╝  ██║  ██║
██████╔╝███████╗   ██║   ███████╗██████╔╝
╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═════╝                                           
                                                             
                            {yellow}GitHub: @hoaxter
                            MadeBy: Nitin Sikarwar''' )


whois_reslut = ""

try:
    print(f"\n{blue}[+] Getting whois info... \n")

    py = whois.query(domain)
    whois_reslut += f'''[+] Name: {py.name} 
[+] Emails: {py.emails}  
[+] Creation: {py.creation_date} 
[+] Expiration: {py.expiration_date} 
[+] Registrar: {py.registrar} 
[+] Regisrtrant: {py.registrant} 
[+] Regisrtrant Country: {py.registrant_country} 
[+] Servers: {py.name_servers} '''
    
except: 
    print(f"{red}[-] Error Occured!")
print(green + whois_reslut)



print(f"\n{blue}[+] Getting DNS info...\n")

dns_result = ""

try:
    for a in dns.resolver.resolve(domain,"A"):
        dns_result += f"[+] A record {a.to_text()} \n"
except:
    print(f"{red}[-] A record DNS Error!")

try:
    for ns in dns.resolver.resolve(domain,"NS"):
        dns_result += f"[+] NS record {ns.to_text()} \n"
except:
    print(f"{red}[-] NS record DNS Error!")

try:
    for mx in dns.resolver.resolve(domain,"MX"):
        dns_result += f"[+] MX record {mx.to_text()} \n"
except:
    print(f"{red}[-] MX record DNS Error!")    

try:
    for txt in dns.resolver.resolve(domain,"TXT"):
        dns_result += f"[+] TXT record {txt.to_text()} \n"
except:
    print(f"{red}[-] TXT record DNS Error!")

print(green + dns_result)




print(f"\n{blue}[+] Getting geolocation info... \n")

geolocation_result = ""

try:
    response = requests.request('GET',"https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()  
    geolocation_result = f'''[+] Country: {response["country_name"]} 
[+] Latitude: {response["latitude"]} 
[+] Longitude: {response["longitude"]}
[+] City: {response["city"]} 
[+] State: {response["state"]} 
[+] IPv4: {response["IPv4"]} '''
except:
    print(f"{red}[-] Error: Can't fetch data \n")

print(green + geolocation_result,"\n")



if ip:
    user_api = input("\nEnter shodan api key if not leave blank: ")
    if user_api == "":
        exit()

    api = shodan.Shodan(user_api) 
    try:
        print(f"{blue}[+] Getting Shodan info for IP:",ip)
        results = api.search(ip)
        
        print("[+] Result found:", results['total'],"\n")
        for result in results['matches']:
            print("[+] IP:",result["ip_str"])
            print("[+] Data:\n",result["data"])
            print()
    
    except Exception as e: 
        print(f"{red}[-] Shodan search error! {e}") 



if output:
    with open(output, "w") as infofile: 
        infofile.write("\n[#] WhoIs Result: \n\n" + whois_reslut + "\n\n[#] DNS Result:\n\n" + dns_result + "\n[#] Geolocation Result:\n\n" + geolocation_result)
 