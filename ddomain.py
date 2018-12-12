#!/usr/bin/python
'''
Custom DNS lookup Tool, DDomain
Version 5.2

Author:  Bleakbriar
Last modified 12/09/2018

'''

import dns.resolver
import sys
import whois
import datetime
import argparse

# Updatable lists for use in Script======================================
# List of nameservers to warn user could be obscuring DNS of domain
obscure = ["cloudflare", "domaincontrol"]
# List of domain status keywords to check WHOIS for and warn if present
StatusAlert = ["hold"]
#========================================================================
'''
Object for looking up and storing DNS information 
for the domain of interest. Stores A, rDNS for 
all A, MX, and NS records using its own DNS 
resolver object
 
'''
class DNS_Object:
	def __init__(self, domain):
		self.domain = domain
		self.res = dns.resolver.Resolver()

# Bulk getters for sets of records; assigns results to member fields of object to be used later
	def get_whois_records(self):
		self.w, self.whois_found = self.get_whois()
		self.NS = self.get_NS()

	def get_main_records(self):
		self.A = self.get_A()
		self.rDNS = self.get_rDNS()
		self.MX = self.get_MX()
		self.NS = self.get_NS()

	def get_mail_records(self):
		self.MX = self.get_MX()
		self.SPF = self.get_SPF()
		self.DKIM = self.get_DKIM()
		self.DMARC = self.get_DMARC()
	
	def get_A(self):
		ret = []
		try:
			A = self.res.query(self.domain, "A")
			for rdata in A:
				ret.append(str(rdata))
			return ret
		except:
			ret.append("Unavailable/Missing")
			return ret
	
	def get_rDNS(self):
		ret = []
		for entry in self.A:
			try:
				rIP = '.'.join(reversed(entry.split("."))) + ".in-addr.arpa"
				rDNS = self.res.query(rIP, "PTR")
				for rdata in rDNS:			
					ret.append(str(rdata))
			except:
				ret.append("Unavailable/Missing")
		return ret

	def get_MX(self):
		ret = []
		try:
			MX = self.res.query(self.domain, "MX")
			for rdata in MX:
				ret.append(str(rdata))
			return ret
		except:
			ret.append("Unavailable/Missing")
			return ret

	def get_NS(self):
		ret = []
		try:
			NS = self.res.query(self.domain, "NS")
			for rdata in NS:
				ret.append(str(rdata))
			return ret
		except:
			ret.append("Unavailable/Missing")
			return ret

	def get_whois(self):
		try:
			w = whois.whois(self.domain)
                	whois_found = True
		except:
			whois_found = False
			w = ''
		return w, whois_found

	def get_SPF(self):
		ret = []
		try:
			SPF = self.res.query(self.domain, "TXT")
			for rdata in SPF:
				if "v=spf1" in str(rdata):
				    ret.append(str(rdata))
			return ret
		except:
			ret.append("Unavailable/Missing")
			return ret

	def get_DKIM(self):
		ret = []
		try:
			DKIM = self.res.query("default._domainkey." + self.domain, "TXT")
			for rdata in DKIM:
				ret.append(str(rdata))
			return ret
		except:
			ret.append("Unavailable/Missing")
			return ret

	def get_DMARC(self):
		ret = []
		try:
			DMARC = self.res.query("_dmarc." + self.domain, "TXT")
			for rdata in DMARC:
				ret.append(str(rdata))
			return ret
		except:
			ret.append("Unavailable/Missing")
			return ret

#===============================================================================
# General Use functions
def whois_NS_match(whois, prop):
	try:
		for entry in whois:
			for ns in prop:
				if(str(ns).lower().find(str(entry).lower()) != -1):	
					return True
		return False
	except:
		print("\t[?] Unable to check nameservers in WHOIS")#need better error message
		return True

def is_Obscured(ns):
	for entry in ns:
		for o in obscure:
			if(str(entry).lower().find(str(o).lower()) != -1):
				return True
	return False

def PvW_NS_mismatch_check(DNS): #Propagated Vs Whois Nameserver mismatch check
        try:
                if(DNS.whois_found):
                        if(whois_NS_match(DNS.w.name_servers, DNS.NS) != True):
                                print("\t[!] Warning: NS records do not match Registrar")
                                for x in xrange(len(DNS.w.name_servers)):
                                        print("\t[!] " + str(DNS.w.name_servers[x]).lower())
        			return True
			else:
				return False
	except:
                print("[!]Can't get Nameserver info")
		return False

def whois_expiration(DNS):
        try:
        	print(DNS.domain.upper() + " expires " + str(DNS.w.expiration_date[0]))
                if(DNS.w.expiration_date[0] < datetime.datetime.now()):
                	print("\t[!] Domain expired")
     	except:
        	try:
                	print(DNS.domain + " expires " + str(DNS.w.expiration_date))
                        if(DNS.w.expiration_date < datetime.datetime.now()):
                        	print("\t[!] Domain expired")
             	except:
                	print("\t[?] Expiration Date not found ...")

def registrar_info(DNS):
	try:
        	# Registrar info is listed differently
                #       depending on the registrar name 
                #       and which whois repo it's being
                #       pulled from, so two methods     
                #       are needed to print properly
                if(len(str(DNS.w.registrar[1])) == 1):
                	print("Registered with " + str(DNS.w.registrar) + "\n")
                else:
                        print("Registered with " + str(DNS.w.registrar[1]) + "\n")
	except:
        	print("\t[?] Registrar not available in standard whois lookup")

def status_info(DNS):
	'''
	Currently shows all domain status messages from whois
	May need to scale back to previous version of this 
	method if found to be too verbose, or limit what
	messages are displayed
	'''
	try:
        	#if "ok" not in DNS.w.status:
                #	print("\t[!] Domain Status Alert")
                #        print("\t\t" + DNS.w.status)
		if "ok" not in DNS.w.status:
		    for status in DNS.w.status:
			for alert in StatusAlert:
			    if alert in status.lower():
				print("\t[!] Domain Status Alert")
				print("\t\t" + status)
   	except:
		try:
			not_okay = False
			status = []
			for r in DNS.w.status:
				if "ok" not in r and "OK" not in r:
		 			not_okay = True
					status.append(r)
			if(not_okay):
				for entry in status:
					index = entry.find(" ")
					print("\t\t" + entry[0:index])
		except:			
			print("[?] Domain status unavailable")
        
# Methods to print blocks of data

def print_whois(DNS):
    if(DNS.whois_found != True):
	print("\t[!] Warning: Domain registration details not found...\n\n")
    #if(is_Obscured(DNS.NS)):
	#print("\t[!] Warning DNS may be obscured and/or hidden")
    whois_expiration(DNS)
    registrar_info(DNS)
    if(is_Obscured(DNS.NS)):
	print("\t[!] Warning: DNS may be obscured and/or hidden")
    status_info(DNS)
    print

def print_records(DNS):
        print
        for entry in DNS.A:
                print("[A] " + entry)
        for entry in DNS.rDNS:
                print("\t[rDNS] " + entry)
        for entry in DNS.MX:
                print("[MX] " + entry)
        for entry in DNS.NS:
                print("\t[NS] " + entry)

def print_email_records(DNS):
	print
	for entry in DNS.MX:
		print("[MX] " + entry)
	for entry in DNS.SPF:
		print("\t[SPF] " + entry)
	for entry in DNS.DMARC:
		print("[DMARC] " + entry)
	for entry in DNS.DKIM:
		print("\t[DKIM] " + entry)
	print


# Main Function ==============================================================
def main(args): # Main function
	# Banner
	print("=" * 25)
	print("*" + " " * 6 + "DDomain 5.2" + " " * 6 + "*")
	print("=" * 25) 

	DNS = DNS_Object(args.domain)
	
	if(args.m_flag):
	    DNS.get_mail_records()
	    DNS.get_whois_records()
	    print_whois(DNS)
	    print_email_records(DNS)
	else:
	    DNS.get_main_records()
	    DNS.get_whois_records()
	    print_whois(DNS)
	    print_records(DNS)
	    print("\n")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Multipurpose domain detective and DNS lookup tool')
	parser.add_argument("domain", help="Domain to look up")
	# optional flags
	parser.add_argument("-m", "--mail",
		help="Query for email specific records: MX, SPF, DKIM, and MARC",
		action="store_true", dest='m_flag', default=False)
	args = parser.parse_args()

	main(args)
