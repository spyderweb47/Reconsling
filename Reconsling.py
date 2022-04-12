#!/usr/bin/env python3

import requests
import subprocess
import os
import sys
from bs4 import BeautifulSoup
import socket
from termcolor import colored


domain=sys.argv[1]


DNULL=open(os.devnull,"w+")


def listToString(s): 
    
    # initialize an empty string
    str1 = "" 
  #   for menu in Options:
		# print(f"{menu}    : {Options[menu]}")
    # traverse in the string  
    for ele in s: 
        str1 +=f"\n{f'[+]> {ele}':<25}: {s[ele]}" 
 
    
    # return string  
    return str1 
        
        


def protocol_striper(name):
	if "https://" in name:
		host = name.replace("https://","")
	else:
		host = name.replace("http://","")
	return host


def cleaner(value):
	newvalue=str(value)
	newvalue=newvalue.strip("{'server': '")
	newvalue=newvalue.strip("'}")
	return newvalue


def req_server(url):
	try:
		response=requests.head(url)
		headers=response.headers
		server = {key: headers[key] for key in headers.keys() & {'server'}} 
		server=cleaner(server)
		return server
	except:
		nope="Not Found"
		return nope

def check_CreationDate(url):
	host=protocol_striper(url)
	Create_date=subprocess.check_output('''whois '''+host+''' |grep -i creation | head -n1 | awk -F ":" '{print $2}' ''',shell=True).decode('utf-8')
	if(len(str(Create_date)) < 4):
		Create_date="Not Found"
	return Create_date

def Check_ExpiryDate(url):
	host=protocol_striper(url)
	Expire_date=subprocess.check_output('''whois '''+host+''' |grep -i 'Expiry Date' | head -n1 | awk -F ":" '{print $2}' ''',shell=True).decode('utf-8')
	if(len(str(Expire_date)) < 4):
		Expire_date="Not Found"
	return Expire_date

def Check_Updation_Date(url):
	host=protocol_striper(url)
	Expire_date=subprocess.check_output('''whois '''+host+''' |grep -i updated | head -n1 | awk -F ":" '{print $2}' ''',shell=True).decode('utf-8')
	if(len(str(Expire_date)) < 4):
		Expire_date="Not Found"
	return Expire_date

def spf_check(urls):
	try:
		url= 'https://www.kitterman.com/spf/getspf3.py'
		obj={'serial':'fred12','domain':urls}

		x = requests.post(url,data=obj)
		string = x.text
		soup = BeautifulSoup(string, 'lxml')
		d=0
		data=[]
		for br_tag in soup.find_all('br'):
			p=br_tag.text,br_tag.next_sibling
			for i in range(len(p)):
				d=p[i]
				#print(d)
			sdata=(str(d).rstrip("\n"))
			ldata=sdata.strip('<br/>')
			data.append(ldata)
		if(len(data)<=5):
			return str("Not Found")
		else:
			return str("Found")
	except:
		return str("Not Found")


def check_cname(url):
	host=protocol_striper(url)
	cname=subprocess.check_output('''dig @8.8.8.8 '''+host+'''|grep -i cname | awk -F " " '{print $5}' ''',shell=True).decode('utf-8')
	return cname

def ip_check(url):
	try:
		host=protocol_striper(url)
		ip=socket.gethostbyname(host)
		return ip
	except:
		return str("Not Found")

def check_organization(url):
	host=protocol_striper(url)
	organization=subprocess.check_output('''whois '''+host+''' |grep -i 'Registrant Organization' | head -n1 | awk -F ":" '{print $2}' ''',shell=True).decode('utf-8')
	if(len(str(organization)) < 4):
		organization="Not Found"
	return organization

def ResHeader(url):
	response=requests.get(url)
	headers=response.headers
	return headers




print(colored(f"[+] Domain       :      {domain}","green"))

ip=ip_check(domain)
print(colored(f"[+] IP           :      {ip}","green"))

server=req_server(domain)
print(colored(f"[+] Server       :      {server}","green")) 

Create_date=check_CreationDate(domain).strip("\n").strip(" ")
print(colored(f"[+] Created on   :      {Create_date}","green"))

update=Check_Updation_Date(domain).strip("\n").strip(" ")
print(colored(f"[+] Updated on   :      {update}","green"))

Expire_date=Check_ExpiryDate(domain).strip("\n").strip(" ")
print(colored(f"[+] Expiry       :      {Expire_date}","green"))

spf=spf_check(domain)
print(colored(f"[+] SPF Records  :      {spf}","green"))

count = domain.count(".")
if(count>1):
	cname=check_cname(domain).strip("\n").strip(" ")
else:
	cname="Not Found"
if(count>1):
	print(colored(f"[+] Cname        :      {cname}","green"))

organization=check_organization(domain).strip("\n").strip(" ")
print(colored(f"[+] Organization :      {organization}","green"))

List=ResHeader(domain)
header=listToString(List)
print(colored("%10s" % f"[+] Headers      :      {header}","green"))


