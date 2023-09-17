import json as thatoneuniversaldataparserformatthatisreallycoolandeveryonelikes, requests as reeeeeeeeeeeeeeeeeeeeeeee
import pprint as makethatoneuniversaldataparserformatthatisreallycoolandeveryonelikespretty
import xml.etree.ElementTree as makethatonetagbaseddataformatthatlooksweirdnotsoweird

ip:str = "[TESTING_IP]"
api_key:str = "[API_KEY]"

class ShodanQueryResponse:
    def __init__(self, vulns:list[str], ports:list[str], domains:list[str], hostnames:list[str], asn:str, os:list[str], tags:list[str], data:list[str]) -> None:
        self.vulns = vulns
        self.ports = ports
        self.domains = domains
        self.hostnames = hostnames
        self.asn = asn
        self.os = os
        self.tags = tags
        self.data = data

class DomainQueryResponse:
    def __init__(self, domain:str, subdomains:list[str], data:list[str]) -> None:
        self.domain = domain
        self.subdomains = subdomains
        self.data = data

class RobotsResponse:
    def __init__(self, allowList:list[str], disallowList:list[str], sitemap:list[str]) -> None:
        self.allowList = allowList
        self.disallowList = disallowList
        self.sitemap = sitemap



class Searcher:
    def __init__(self, ip:str, key:str) -> None:
        self.ip = ip
        self.key = key

    def hostData(self) -> ShodanQueryResponse:
        resp = reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/host/{HOST_IP}?key={KEY}".format(HOST_IP=self.ip, KEY=self.key)).content
        data = thatoneuniversaldataparserformatthatisreallycoolandeveryonelikes.loads(resp)
        #print(pResp["data"][0]["product"])
        return ShodanQueryResponse(data["vulns"], data["ports"], data["domains"], data["hostnames"], data["asn"], data["os"], data["tags"], data["data"])

    def nmap(self, hostData:ShodanQueryResponse) -> None:
        for serviceBlock in hostData.data:
            print(f"{serviceBlock['port']}/{serviceBlock['transport']} {serviceBlock['_shodan']['module']} {serviceBlock['product']}")


    def retAllDataTESTING(self, hostData:ShodanQueryResponse) -> None:
        print(f"\nASN: {hostData.asn}") # write ASN lookup function

        print("\nDomains:")
        for domain in hostData.domains:
            print(domain)

        print("\nHostnames:")
        for hostname in hostData.hostnames:
            print(hostname)
        
        print("\n")

        #print(f"\nOS: {hostData.os}")

        #print("\nVulns:")
        #for vuln in hostData.vulns:
        #    print(vuln)

class Scanner:
    def __init__(self, key) -> None:
        self.key = key

    def allShodanPorts(self) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/ports?key={KEY}"
                                             .format(KEY=self.key)).content
    def allShodanProtocols(self) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/protocols?key={KEY}"
                                             .format(KEY=self.key)).content
    
    def allScans(self) -> str:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/scans?key={KEY}"
                                             .format(KEY=self.key)).content

    def scanStatus(self, id:str) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/scan/{ID}?key={KEY}"
                                             .format(ID=id, KEY=self.key)).content
    
class Alerter:
    def __init__(self, key) -> None:
        self.key = key

    def alertInfo(self, id:str) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/alert/{ID}/info?key={KEY}"
                                             .format(ID=id, KEY=self.key)).content
    
    def allAlertInfo(self) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/alert/info?key={KEY}"
                                             .format(KEY=self.key)).content

    def getAllTriggers(self) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/alert/triggers?key={KEY}"
                                             .format(KEY=self.key)).content
    
class Notifier:
    def __init__(self, key) -> None:
        self.key = key

    def getAllNotifiers(self) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/notifier?key={KEY}"
                                             .format(KEY=self.key)).content
    
    def getAllProviders(self) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/notifier/provider?key={KEY}"
                                             .format(KEY=self.key)).content
    
    def getNotifier(self, id:str) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/notifier/{ID}?key={KEY}"
                                             .format(KEY=self.key, ID=id)).content

class DNSer:    
    def resolve(hostnames:str, key:str) -> bytes:
        #for(string hostname in hostnames):
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/dns/resolve?hostnames={HOSTNAMES}&key={KEY}"
                                             .format(HOSTNAMES=hostnames, KEY=key)).content
    
    def reverse(ips:str, key:str) -> bytes:
            #for(string ip in ips):
            return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/dns/reverse?ips={IPS}&key={KEY}"
                                                 .format(IPS=ips, KEY=key)).content

class WebHunter:
    def retDomainData(domain:str, key:str) -> DomainQueryResponse:
        resp = reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/dns/domain/{DOMAIN}?key={KEY}".format(DOMAIN=domain, KEY=key)).content.decode("utf-8")
        pResp = thatoneuniversaldataparserformatthatisreallycoolandeveryonelikes.loads(resp)

        return DomainQueryResponse(pResp["domain"], pResp["subdomains"], pResp["data"])
    
    def robotsHunter(domain:str) -> RobotsResponse:
        #if (domain has http)
        resp = reeeeeeeeeeeeeeeeeeeeeeee.get(f"http://{domain}/robots.txt").content.decode("utf-8")

        allowList = []
        disallowList = []
        sitemap = ""

        for line in resp.split("\n"):
            if (line.split(":")[0] == "Allow"):
                #print(f"ALLOW: {line.split(' ')[1]}")
                allowList.append(line.split(' ')[1])
            if (line.split(':')[0] == "Disallow"):
                #print(f"DISALLOW: {line.split(' ')[1]}")
                disallowList.append(line.split(' ')[1])
            if (line.split(':')[0] == "Sitemap"):
                #print(f"SITEMAPS: {line.split(' ')[1]}")
                sitemap = line.split(' ')[1]

        return RobotsResponse(allowList, disallowList, sitemap)
    
    def sitemapCrawler(sitemap:str) -> None:
        resp = reeeeeeeeeeeeeeeeeeeeeeee.get(sitemap).content.decode("utf-8")
        print(resp)
        tree = makethatonetagbaseddataformatthatlooksweirdnotsoweird.ElementTree(makethatonetagbaseddataformatthatlooksweirdnotsoweird
                                                                                 .fromstring(resp))
        root = tree.getroot()

        #print(root)
        
        #print(root[0][0].text)
        #print(root[1][0].text)
        #print(root[2][0].text)
        #print(root[3][0].text)
        
         
class Utils:
    def getAllQueries(key:str) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/query?key={KEY=key}"
                                             .format(KEY=key)).content
    
    def getAllSearchQueries(key:str) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/query/search?key={KEY}"
                                             .format(KEY=key)).content
    
    def getAllUsedTags(key:str) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/shodan/query/tags?key={KEY}"
                                             .format(KEY=key)).content.decode("utf-8")
    
    def getAccInfo(key:str) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/account/profile?key={KEY}"
                                             .format(KEY=key)).content.decode("utf-8")

    def getAPIInfo(key:str) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/api-info?key={KEY}"
                                             .format(KEY=key)).content.decode("utf-8")
    
    def getCurrentIP(key:str) -> bytes:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/tools/myip?key={KEY}"
                                             .format(KEY=key)).content.decode("utf-8").split('"')[1]

    def getClientHeaders(key:str) -> str:
        return reeeeeeeeeeeeeeeeeeeeeeee.get("https://api.shodan.io/tools/httpheaders?key={KEY}"
                                             .format(KEY=key)).content
    def dec2ip(ip:str) -> str:
        return ""
    
    def asnLookup(asn:str) -> str:
        return ""
    
    def APICheck() -> bool:
        return True

searcherObj = Searcher(ip, api_key)

domainDataResp:DomainQueryResponse = WebHunter.retDomainData("[DOMAIN]", api_key)

sitemaps = []

for subdomain in domainDataResp.subdomains:
    print(f"{subdomain}.{domainDataResp.domain}")
    robots:RobotsResponse = WebHunter.robotsHunter(f"{subdomain}.{domainDataResp.domain}")
    print(f"ALLOW: {robots.allowList}")
    print(f"DISALLOW: {robots.disallowList}")
    print(f"SITEMAP: {robots.sitemap}")
    sitemaps.append(robots.sitemap)
    print("\n")

for sitemap in sitemaps:
    print(f"{sitemap}:\n")
    WebHunter.sitemapCrawler(sitemap)
    print("\n")