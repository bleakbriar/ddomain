#!/usr/bin/python
#Custom DNS lookup Tool, DDomain
#Version 5.0
#Author:  Bleakbriar
#Last modified 02/07/2018


import dns.resolver
import sys
import whois
import datetime
import argparse

# List of nameservers that can obscure DNS
obscure = ["cloudflare", "domaincontrol"]

#========================================================================
#Object for looking up and storing DNS information 
#for the domain of interest. Stores A, rDNS for 
#all A, MX, and NS records using its own DNS 
#resolver object

class DNS_Object:
        def __init__(self, domain):
                self.domain = domain
                self.w, self.whois_found = self.get_whois()
                self.res = dns.resolver.Resolver()
                self.A = self.get_A()
                self.rDNS = self.get_rDNS()
                self.MX = self.get_MX()
                self.NS = self.get_NS()


        def get_A(self):
                ret = []
                try:
                        A = self.res.query(self.domain, "A")
                        for rdata in A:
                                ret.append(str(rdata))
                        return ret
                except:
                        ret.append("Unavailable...")
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
                                ret.append("Unavailable...")
                return ret


        def get_MX(self):
                ret = []
                try:
                        MX = self.res.query(self.domain, "MX")
                        for rdata in MX:
                                ret.append(str(rdata))
                        return ret
                except:
                        ret.append("Unavailable...")
                        return ret

                        

        def get_NS(self):
                ret = []
                try:
                        NS = self.res.query(self.domain, "NS")
                        for rdata in NS:
                                ret.append(str(rdata))
                        return ret
                except:
                        ret.append("Unavailable...")
                        return ret


        def reset_Resolver(self, resolver):
                self.res = resolver
                self.A = self.get_A()
                self.rDNS = self.get_rDNS()
                self.MX = self.get_MX()
                self.NS = self.get_NS()
        
        def get_whois(self):
                try:
                        w = whois.whois(self.domain)
                        whois_found = True
                except:
                        whois_found = False
                        w = ''
                return w, whois_found
#===============================================================================
# General functions
def whois_NS_match(whois, prop):
        try:
                for entry in whois:
                        for ns in prop:
                                if(str(ns).lower().find(str(entry).lower()) != -1):     
                                        return True
                return False
        except:
                #need better error message
                print("\t[?] Unable to check nameservers in WHOIS")
                return True


def is_Obscured(ns):
        for entry in ns:
                for o in obscure:
                        if(str(entry).lower().find(str(o).lower()) != -1):
                                return True
        return False


# Divergent functions
#=============================================================================
#Functions used by all runs regardless of what
#options are passed to the script, but run
#with different resolvers

def PvW_NS_mismatch_check(DNS):
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
                print(DNS.domain + " expires " + str(DNS.w.expiration_date[0]))
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
        #Currently shows all domain status messages from whois
        #May need to scale back to previous version of this 
        #method if found to be too verbose, or limit what
        #messages are displayed
        try:
                if "ok" not in DNS.w.status:
                        print("\t[!] Domain Status Alert")
                        print("\t\t" + DNS.w.status)
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


# Main Function
# ============================================================================
def main(args): # Main function
        
        # Banner
        print("=" * 25)
        print("*" + " " * 7 + "DDomain 5" + " " * 7 + "*")
        print("=" * 25) 

        DNS = DNS_Object(args.domain)
        # Check flags for CLI options
        p_flag = False
        if(args.i_flag == False and args.w_flag == False and args.s_flag == False):
                p_flag = True
        if(args.p_flag == True or args.r_flag == True):
                p_flag = True   
        # Check for whois and obscured DNS
        if(DNS.whois_found != True):
                print("\t[!] Warning: Domain registration not found...\n\n")

        if(is_Obscured(DNS.NS)):
                print("\t[!] Warning: DNS may be obscured and/or hidden")
                
        # General lookups
        whois_expiration(DNS)
        registrar_info(DNS)
        status_info(DNS)
        print# Layout ...

        # option specific checks
        whois_mismatch = False
        if(p_flag):
                whois_mismatch = PvW_NS_mismatch_check(DNS)
                print_records(DNS)
                print("\n")

        if(whois_mismatch and args.r_flag):
                print("\n[*] Quering Registrar listed nameservers...")
                sys_r = dns.resolver.Resolver()
                r_dns = [item.address for server in DNS.NS for item in sys_r.query(server)]     
                r_res = dns.resolver.Resolver()
                r_res.namservers = r_dns
                DNS.reset_Resolver(r_res)
                print_records(DNS)
                print("\n")

        if(args.i_flag):
                print("\n[*] Quering InMotionHosting.com nameservers...")
                sys_r = dns.resolver.Resolver()
                ns = ['ns1.inmotionhosting.com', 'ns2.inmotionhosting.com']
                imh_dns = [item.address for server in ns for item in sys_r.query(server)]
                imh_res = dns.resolver.Resolver()
                imh_res.namservers = imh_dns
                DNS.reset_Resolver(imh_res)
                PvW_NS_mismatch_check(DNS)
                print_records(DNS)
                print("\n")     
        
        if(args.w_flag):
                print("\n[*] Quering WebHostingHub.com nameservers...")
                sys_r = dns.resolver.Resolver()
                ns = ['ns1.webhostinghub.com', 'ns2.webhostinghub.com']
                hub_dns = [item.address for server in ns for item in sys_r.query(server)]
                hub_res = dns.resolver.Resolver()
                hub_res.nameservers = hub_dns
                DNS.reset_Resolver(hub_res)
                PvW_NS_mismatch_check(DNS)
                print_records(DNS)
                print("\n")

        if(args.s_flag):
                print("\n[*] Quering ServConfig.com nameservers...")
                sys_r = dns.resolver.Resolver()
                ns = ['ns1.servconfig.com', 'ns2.servconfig.com']
                serv_dns = [item.address for server in ns for item in sys_r.query(server)]
                serv_res = dns.resolver.Resolver()
                serv_res.nameservers = serv_dns
                DNS.reset_Resolver(serv_res)
                PvW_NS_mismatch_check(DNS)
                print_records(DNS)
                print("\n")

if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument("domain", help="Domain to look up")
        # optional flags
        parser.add_argument("-i", "--inmotion", 
                help="Query InMotionHosting.com nameservers directly",
                action="store_true", dest='i_flag', default=False)
        parser.add_argument("-s", "--servconfig",
                help="Query ServConfig.com nameservers directly",
                action="store_true", dest='s_flag', default=False)
        parser.add_argument("-w", "--webhostinghub",
                help="Query WebHostingHub.com nameservers directly",
                action="store_true", dest='w_flag', default=False)
        parser.add_argument("-p", "--propagated",
                help="Use with other flags to query propagated DNS as well",
                action="store_true", dest='p_flag', default=False)
        parser.add_argument("-r", "--registrar",
                help="Query nameservers listed with registrar if different from propagated NS records",
                action="store_true", dest='r_flag', default=False)
        args = parser.parse_args()

        main(args)
