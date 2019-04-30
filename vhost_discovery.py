#!/usr/bin/python
import requests
import argparse
import sys
sys.path.insert(0, "imports/")
from logger import *
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import hashlib
import time

NON_EX_LEN = 0 # define what is the length of no existent response
PROXS = {
	'http': '127.0.0.1:8080',
	'https': '127.0.0.1:8080',
}


parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target',required=True,help='Target hostname in the format http://TARGET')
parser.add_argument('-n', '--hostname',required=False,help='Base hostname . (e.g. hack.com)')
parser.add_argument('-e', '--headers',required=False,help='Additional headers in the form \'Head1:value,Head2:value,...\'')
parser.add_argument('-p', '--prefix',required=False,default='list/common_prefix.txt',help='File with a list of prefixS')
parser.add_argument('-f', '--fuzz',required=False,default='list/common_prefix.txt',help='File with a list of prefixS')
parser.add_argument('-s', '--sleep',required=False,default=0,help='Sleep between each reqeust. Default 0')
parser.add_argument('-dd', '--debug', action='store_true' ,default=False, required=False, help='Run in debug mode')

args = vars(parser.parse_args())
set_debug(args['debug'])


def get_info_leak(lTarget,lBaseHost):
	# Get a light info leak from Headers
	
	interesting_headers = ['server','x-powered-by','x-oracle-dms-ecid','x-generated-by','kbn-name','kbn-version','kbn-xpack-sig']
	# Loading custom arg headers
	heads = {}
	if args['headers']:
		print_info('Loading custom headers...')
		custom_headers = get_arg_headers(args['headers'])
		heads.update(custom_headers)
	heads.update({'Host':lBaseHost})
	reqHead = requests.get(lTarget,headers=heads,verify=False,proxies=PROXS)
	
	for name,value in reqHead.headers.items():
		if name.lower() in interesting_headers:
			print_ok('\t ' + name + ': ' + value )


def get_arg_headers(lHeaders):
	formattedHeaders = lHeaders.split(',')
	dictHeaders = {}
	for head in formattedHeaders:
		name = head.split(':')[0]
		val = head.split(':')[1]
		dictHeaders.update({name:val})
	return dictHeaders

def gen_md5(content):
	m = hashlib.md5()
	m.update(content)
	return m.hexdigest()

def make_req(lTarget, targetHead):
	# Make request and return len of the response
	time.sleep(float(args['sleep']))
	heads = {
		'Host': targetHead
	}
	# Add custom headers if specified	
	if args['headers']:
		print_info('Loading custom headers...')
		custom_headers = get_arg_headers(args['headers'])
		heads.update(custom_headers)


	if 1==2:
		req = requests.get(target, headers=heads)
	else:
		# Burp debug
		req = requests.get(target, headers=heads, verify=False, proxies=PROXS)
	return gen_md5(req.text)



def get_non_ex_len(lTarget, lBaseHost):
	# Define NON_EX_LEN. for now is only static
	rand_str = { 'ASsdsadaSDFJION','LJOILOJIHKwdsdsdsdB','HKGFVCHvgftucjsvdsd',}
	non_ex = 0
	non_ex_tmp = 0
	first = True
	for rand in rand_str:
		if first:
			non_ex = make_req(lTarget,rand + '.'+ lBaseHost)
			first = False
		else:
			non_ex_tmp = make_req(lTarget, rand + '.'+ lBaseHost)
			if non_ex_tmp != non_ex:
				return False
	return non_ex

## START ##
# Check if the the hostname is specified . use the target URL if not.
target = args['target']
if args['hostname']:
	baseHost = args['hostname']
else:
	baseHost = target.replace('http://','').replace('https://','')
####

# READING prefix file
prefixFile = args['prefix']
hPrefixFile = open(prefixFile)
data = hPrefixFile.readlines()
wordlist = []
for line in data:
	wordlist.append(line.replace('\n',''))
hPrefixFile.close()
####

print_info('Starting first info leak..')
get_info_leak(target,baseHost)
### DETERMINE CHE NON_EX_LENGHT
NON_EX_LEN = get_non_ex_len(target,baseHost)
if NON_EX_LEN == 0 or NON_EX_LEN is False:
	print_error('Couldn\'t determine length of failed VHOST .. exit')
	sys.exit(0)
###

print_debug('MD5 of failed VHOST: ' + str(NON_EX_LEN))

# BRUTE VHOSTs
results = []
for prefixName in wordlist:
	hostField = prefixName + baseHost
	ret_len = make_req(target,hostField)
	if ret_len != NON_EX_LEN:
		print_ok('VHOST FOUND: ' + hostField)
		results.append(hostField)
	else:
		print_warning('Nothing at ' + hostField)
		

### Send results to the user
if not results:
	print_info('Nothing found ...')
else:
	print_info('RESULTS:')
	for v in results:
		print_info('Info leak for ' + v + ':')
		get_info_leak(target,v)
		print v
###