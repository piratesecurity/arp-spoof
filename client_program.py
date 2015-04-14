#################################################################
# Modules for Implementing Client Functionality
# Client Program for sending Register message to Server.
# Developed by piratesecurity
#################################################################

from scapy.all import *
import os
import time
import atozmod

# For Loopback IP addresse
#conf.L3socket = L3RawSocket for localhost


# Global Varialbes

interface=atozmod.interface
server_ip_address=atozmod.server_ip_address
server_mac_address=atozmod.server_mac_address
client_ip_address=atozmod.get_ip_address()
client_mac_address=atozmod.get_mac_address()

# Adding Static ARP entry for Server
os.system("sudo arp -i "+interface+" -s "+server_ip_address+" "+server_mac_address)


# Functions

def request_for_key():	
	message="|Request_Key|"+client_ip_address+"|"+client_mac_address
	atozmod.send_packet(message)
	
def verify_key(client_key):	
	message="|Key|"+client_key
	atozmod.send_packet(message)	

		
try:	
	read_key_file=open("client_key","r")
	client_key=read_key_file.read().split("\n")[0].split("|")[1]
	verify_key(client_key)
	
except IOError,IndexError:
	request_for_key()


def read_packet(pkt):
	try:	
		register_ip=pkt[IP].src	
		register_mac=pkt.src
		print "Data Recieved from: ",register_ip,register_mac
		data=pkt[IP].load
	except IndexError:
		print "Packet has No Network layer"
	

def plain_sniff():
	sniff(iface=interface,prn=read_packet,filter="dst port 45001")
	
plain_sniff()
