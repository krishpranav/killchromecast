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