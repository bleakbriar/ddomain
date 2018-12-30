#!/usr/bin/python
'''
Experimental custom whois query tool
For use with the ddomain DNS tool

Author: Bleakbriar
Last Modified: 12/30/18

'''
import sys
import socket
from datetime import datetime as dt
import time



def whois(domain):
    tld = domain.split('.')[-1]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.nic." + tld, 43))
    s.send((domain + '\r\n').encode())
    
    startTime = time.mktime(dt.now().timetuple())
    timeLimit = 3
    ret = b""

    while True:
	delta = time.mktime(dt.now().timetuple()) - startTime
	data = s.recv(4096)
	ret += data
	if(not data) or (delta >= timeLimit):
	    break
    s.close()
    print(ret.decode())


def main():
    domain = sys.argv[1];
    whois(domain)

if __name__ == "__main__":
    main()
