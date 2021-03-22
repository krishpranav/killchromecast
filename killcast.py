#!/usr/bin/env python3

#imports
import os
import sys
import json
import time
import socket
import requests
import argparse
import ipaddress
from xml.etree import ElementTree
requests.packages.urllib3.disable_warnings()

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

version = '1.0.3'

parser = argparse.ArgumentParser(description="Manipulate Chromecast Devices is your Network")
parser.add_arguments('-t', '--ip', help='IP Address of Chromecast', required=True)
args = parser.parse_args()
ip = args.ip

priv_ip = False

if ipaddress.ip_address(ip).is_private:
	priv_ip = True
else:
	pass

http_port = '8080'
https_port = '8443'
http_header = {'Content-Type': 'application/json'}
https_header = {'Content-Type': 'application/json', 'Authorization':'kill.cast'}

def banner():
	text = r'''
	KILLCHROMECAST
	'''

def var_check():
	print(G + '[+]' + C + ' Checking for Updates...', end='')
	ver_url = 'https://raw.githubusercontent.com/krishpranav/killchromecast/master/version.txt'
	try:
		ver_reqst = requests.get(ver_url, timeout=5)
		var_sc = ver_rqst.status_code
		if ver_sc == 200:
			github_ver = ver_rqst.text()
			github_ver = github_ver.strip()
			if version == github_ver:
				print(C + '[' + G + ' Up-To-Date ' + C +']' + '\n')
			else:
				print(C + '[' + G + ' Available : {} '.format(github_ver) + C + ']' + '\n')
		else:
			print(C + '[' + R + ' Status : {} '.format(ver_sc) + C + ']' + '\n')
	except Exception as e:
		print('\n\n' + R + '[-]' + C + ' Exception : ' + W + str(e))

def conn_test():
	http_test = False
	https_test = False
	print('\n' + Y + '[!] Testing Connection...' + W + '\n')
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.settimeout(5)
		try:
			s.connect((ip, int(http_port)))
			http_test = True
		except OSError:
			print(R + '[-]' + C + ' Exception : ' + W + 'Cannot Connect to Port 8008')
	
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.settimeout(5)
		try:
			s.connect((ip, int(https_port)))
			https_test = True
		except OSError:
			print(R + '[-]' + C + ' Exception : ' + W + 'Cannot Connect to Port 8443')

	if http_test == False or https_test == False:
		print(R + '[-]' + C + ' Connection Test Failed' + W)
		sys.exit()
	else:
		print(G + '[+]' + C + ' Connection Test Passed' + W)

	
