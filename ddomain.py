#!/opt/imh-python/bin/python
# Custom DNS lookup Tool
# By Bleakbriar
#

# Last modified 9/26/17



import dns.resolver
import sys
import whois
import datetime

# List of nameservers that can obscure DNS
obscure = ["cloudflare", "domaincontrol"]

#========================================================================
class DNS_Object:
	def __init__(self, domain):
		self.domain = domain
		self.res = dns.resolver.Resolver()
		self.A = self.get_A()
		self.rDNS = self.get_rDNS()
		self.MX = self.get_MX()
		self.NS = self.get_NS()

	def get_A(self):
		req = []
		try:
			A = self.res.query(self.domain, "A")
			for rdata in A:
				req.append(str(rdata))
			return req
		except:
			req.append("Unavailable...")
			return req
	
	def get_rDNS(self):
		req = []
		for entry in self.A:
			try:
				rIP = '.'.join(reversed(entry.split("."))) + ".in-addr.arpa"
				rDNS = self.res.query(rIP, "PTR")
				for rdata in rDNS:			
					req.append(str(rdata))
			except:
				req.append("Unavailable...")
		return req

	def get_MX(self):
		req = []
		try:
			MX = self.res.query(self.domain, "MX")
			for rdata in MX:
				req.append(str(rdata))
			return req
		except:
			req.append("Unavailable...")
			return req
			

	def get_NS(self):
		req = []
		try:
			NS = self.res.query(self.domain, "NS")
			for rdata in NS:
				req.append(str(rdata))
			return req
		except:
			req.append("Unavailable...")
			return req

	def reset_Resolver(self, IP1, IP2):
		try:
			self.res.nameservers = [IP1, IP2]
			self.A = get_A()
			self.rDNS = get_rDNS()
			self.NS = get_NS()
			self.MX = get_MX()
		except:
			print("\t[?] Warning: unable to get DNS from Registrar NS")
#===============================================================================
# General functions
def whois_NS_match(whois, prop):
	req = True
	try:
		for entry in whois:
			for ns in prop:
				if(str(ns).lower().find(str(entry).lower()) != -1):	
					return True
		return False
	except:
		print("\t[?] Unable to check whois NS")
		return True
def is_Obscured(ns):
	for entry in ns:
		for o in obscure:
			if(str(entry).lower().find(str(o).lower()) != -1):
				return True
	return False

# Main Functioin
# ============================================================================

def main(argv): # Main function
	if(len(argv) < 2): 
		print("[!] Usage: ddomain <domain.name>")
		sys.exit()
	
	# Banner
	print("=" * 25)
	print("|" + " " * 7 + "DDomain 4" + " " * 7 + "|")
	print("=" * 25) 

	domain = argv[1]
	try: # Get whois or warn no registration found
		w = whois.whois(domain)
	except:
		print("\t[!] Warning: Domain registration not found...\n\n")
		w = False
	propDNS = DNS_Object(domain)
	regDNS = ""
	if(is_Obscured(propDNS.NS)  == True):
		print("\t[!] Warning: DNS may be obscured and/or hidden") 
	if(w != False):
		if(whois_NS_match(w.name_servers, propDNS.NS) != True):
			print("\t[!] Warning: Propagated NS do not match Registrar")
			for x in xrange(len(w.name_servers)):
				print("\t[!] " + str(w.name_servers[x]))
			registrar_mismatch = True
			regDNS = DNS_Object(domain)
			# Need to get w.name_servers IP
			# Call regDNS.reset_Resolver
	if(w != False):
		try:
			print(domain + " expires " + str(w.expiration_date[0]))
			if(w.expiration_date[0] < datetime.datetime.now()):
				print("\t[!] Domain expired")
		except:
			print(domain + " expires " + str(w.expiration_date))
			if(w.expiration_date < datetime.datetime.now()):
				print("\t[!] Domain expired")
		try:
			if(len(str(w.registrar[1])) == 1):
				print("Registered with " + str(w.registrar) + "\n")
			else:
				print("Registered with " + str(w.registrar[1]) + "\n")
		except:
			print("\t[?] Registrar not available in standard whois lookup")
		try:
			if "ok" not in w.status:
				print("\t[!] Domain Status Alert")
				print("\t" + w.status)
		except:
			print("[?] Domain status unavailable")
	else:
		print("[?] Domain expiration and registrar not available")
		
	print
	for entry in propDNS.A:
		print("[A] " + entry)
	for entry in propDNS.rDNS:
		print("\t[rDNS] " + entry)
	for entry in propDNS.MX:
		print("[MX] " + entry)
	for entry in propDNS.NS:
		print("\t[NS] " + entry)


if __name__ == "__main__":
	main(sys.argv)
