Ddomain
==============

The domain detective DNS lookup tool
--------------
A custom DNS lookup tool designed for use in webhosting and general DNS troubleshooting applications.  Written in python, the script is called in the format:
  ddomain domain.tld
This will query whois and the propagated DNS records for the following information:
- Registrar
- Expiration date
- Domain status as reported by registrar
- A records
- rDNS lookup of those A records
- MX records
- NS records

The output also displays warnings if the domain is using nameservers known to obsure DNS records like CloudFlare and domaincontrol, if the domain has expired, and if the domains status is reported as anything other than 'Ok'
