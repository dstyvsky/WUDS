
import sys
import os
import datetime
from scapy.all import *
import smtplib
from humanfriendly.tables import format_pretty_table
from termcolor import colored

fromaddr = '<youremail@gmail.com'
toaddrs = '@vtext.com'
looking_for = "yourmac"
msg = "Home!"
password = 'yourpassword'
interface = "mon0"
alreadysent = 0
unique_macs = 0
unique_clients = 0
unique_hosts = 0

class Client(object):
	def __init__(self, mac, last_seen, ssid_name, strength, vendor, host):
		self.mac = mac
		self.last_seen = last_seen
		self.ssid = [ssid_name]
		self.strength = strength
		self.vendor = vendor
		self.host = host
		

def makeClient(mac, last_seen, ssid, strength, vendor, host):
	global unique_macs, unique_clients, unique_hosts
	unique_macs += 1
	if host == False:
		unique_clients+=1
	else:
		unique_hosts +=1
	new_client = Client(mac, last_seen, ssid, strength, vendor, host)
	return new_client

observed_clients = []
def send_text_plain(p):
	global alreadysent

	if p.addr2 ==  looking_for and alreadysent == 0:
		#sendText()
		alreadysent = 1

def sendText():
	server = smtplib.SMTP('smtp.gmail.com:587')
	server.starttls()
	server.login(fromaddr, password)
	server.sendmail(fromaddr, toaddrs, msg)
	server.quit()

def timemgmt():
	time = datetime.datetime.now()
	if time.hour > 4 and time.hour < 24:
		adjusted_hour = time.hour -5
	else:
		adjusted_hour = time.hour + 19

	time = time.replace(microsecond=0, hour = adjusted_hour)
	return time

def find_vendor(mac):
	text = [0,0,]
	text[1] = "NA"
	mac_id = mac[:8]
	vendors = open("vendors.txt")
	for line in vendors.readlines():
		if mac_id.upper() in line:
			text = line.split()
	return text[1]

def update_or_add(p, sig, time, host):
	flag = 0
	for current_client in observed_clients:
		if current_client.mac == p.addr2:
			if p.info not in current_client.ssid and p.info is not '':
				current_client.ssid.append(p.info)
			current_client.last_seen = time
			current_client.strength = sig
			flag = 1
	if flag==0:
		vendor = find_vendor(p.addr2)
		current_client = makeClient(p.addr2, time, p.info, sig, vendor, host)
		observed_clients.append(current_client)


def sniffmgmt(p):
	#Declares Client packet tyes
    	stamgmtstypes = (0, 2, 4)

	#Convert to EST Military time
	time = timemgmt()

	#Looks for probe requests
        if p.haslayer(Dot11):
		#Parses signal strength
		sig = -(256-ord(p.notdecoded[-4:-3]))

		if p.type ==0 and p.subtype == 8:
			host = True
			update_or_add(p, sig, time, host)		

		if p.type == 0 and p.subtype in stamgmtstypes:
			send_text_plain(p)

			#Parses signal strength from packet
			
			host = False

			update_or_add(p, sig, time, host)
			

		        
			
			#sort by signal strength
			global observed_clients
			observed_clients = sorted(observed_clients, key=lambda x: x.last_seen, reverse=True)
			
			show_output()
			

def show_output():
	count = 0
	header = ["MAC", "Vendor", "Time", "Sig", "SSID"]
	current_output = []
	nice_ssids = ""


	for i in range(0,17):
 		current_output.append([])

	for i in range(0, len(observed_clients)):
		if count < 17:
			nice_ssids = ""	
			for s in observed_clients[i].ssid:	
				if s is not "" and s not in nice_ssids:
					nice_ssids = nice_ssids + s + " "
					nice_ssids = nice_ssids[:30]
			nice_time = str(observed_clients[i].last_seen.hour) + ":" + str(observed_clients[i].last_seen.minute) + ":" + str(observed_clients[i].last_seen.second)
			if observed_clients[i].host == True:
				nice_time = colored(nice_time, 'red')
				nice_ssids = colored(nice_ssids, 'red')
				current_output[i] = ([    colored(str(observed_clients[i].mac[9:]), 'red')  , colored(observed_clients[i].vendor, 'red'), nice_time,  colored(str(observed_clients[i].strength), 'red'), nice_ssids])
			else:				
				current_output[i] = ([ str(observed_clients[i].mac[9:])    , observed_clients[i].vendor, nice_time,str(observed_clients[i].strength), nice_ssids])
			
		count += 1
		
	os.system('clear')

	
			
	print (format_pretty_table( current_output, header))
	print "Clients:", unique_clients,"  Hosts:", unique_hosts
	sys.stdout.softspace=0

	
#Calls the Scapy sniff function that drives the program forward
sniff(iface=interface, prn=sniffmgmt)
