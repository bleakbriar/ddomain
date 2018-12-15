Ddomain
==============

The domain detective DNS lookup tool
--------------
A custom DNS lookup tool designed for use in webhosting and general DNS troubleshooting
applications.  Written in python, ddomain provides quick access to relevent DNS queries and
registration information on the provided domain. Ddomain provides several options as to the suite of
records any given query provides, from a general overview to records specifically related to email.

The output also displays warnings if the domain is using nameservers known to obsure DNS 
records like CloudFlare and domaincontrol, if the domain has expired, and if the domain is under a
registrar hold.

Requires the dnspython and python-whois modules for Python 2.7, both of which are installable
through pip:

pip install dnspython
pip install python-whois
