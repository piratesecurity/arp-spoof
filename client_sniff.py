#################################################################
# Modules for Implementing Client Sniffer
# This is client sniffer program which captures the messages from the server and Creates static ARP Entries.
# Developed by piratesecurity
#################################################################

from scapy.all import *
import os
import sys
import atozmod
			

#Global varialbles

interface=atozmod.interface
server_ip_address=atozmod.server_ip_address
server_mac_address=atozmod.server_mac_address

# Add Server Static Entry 

os.system("sudo arp -s "+server_ip_address+" "+server_mac_address)
client_ip_address=atozmod.get_ip_address()
client_mac_address=atozmod.get_mac_address()



# Functions

def write_to_file(mac,key):
	print "Key Successfully Write to File"
	write_key=open("client_key","w")
	write_key.write(client_mac_address+"|"+key+"\n")


def verify_sender(sender_ip,sender_mac):
	if sender_ip==server_ip_address and sender_mac==server_mac_address:
		return True
	else:
		return False


def create_arp_entries(ip_mac_pairs):	
	print "Creating New ARP entries"
	ip_mac_hosts=[]
	ip_mac_dict=dict()
	try:		
		read_hosts_file=open("hosts","r").read()
		ip_mac_hosts=read_hosts_file.split("\n")
		ip_mac_hosts=ip_mac_hosts[:len(ip_mac_hosts)-1]
	except IOError:
		os.system("touch hosts")
	ip_mac_pairs=ip_mac_pairs.split("\n")
	ip_mac_pairs=ip_mac_pairs[:len(ip_mac_pairs)-1]
	for ip_mac in ip_mac_hosts:
		ip_mac=ip_mac.split(" ")
		ip_mac_dict[ip_mac[1]]=ip_mac[0]	
	print ip_mac_pairs
	print ip_mac_dict	
	write_to_file=open("hosts","a")
	for pair in ip_mac_pairs:
		ip_mac=pair.split(" ")	
		print ip_mac,"works"	
		if ip_mac[1]!=client_mac_address and ip_mac[1] not in ip_mac_dict.keys():
			write_to_file.write(ip_mac[0]+" "+ip_mac[1]+"\n")
			print "New ARP entry added ",ip_mac[0],ip_mac[1]				
			os.system("sudo arp -s "+ip_mac[0]+" "+ip_mac[1])
	
def read_server_message(data_split,sender_mac):
	print "New Packet Recieved",data_split
	try:
		
		type_data=data_split[1]
		if type_data=="New_Key":
			client_key=data_split[2]
			message="|Key|"+client_key
			write_to_file(sender_mac,client_key)
			atozmod.send_packet(message)

		elif type_data=="Response_Message":				
			create_arp_entries(data_split[2])
		elif type_data=="Message":
			print data_split[2]
		elif type_data=="Update_Message":
			create_arp_entries(data_split[2])			
	except IndexError:
		print "Error Occured While splitting of Server Message"

def read_packet(pkt):
	try:
		sender_ip=pkt[IP].src	
		sender_mac=pkt.src
		if verify_sender(sender_ip,sender_mac)==True:
			data=pkt[IP].load
			data_split=data.split("|")			
			read_server_message(data_split,sender_mac)

	except IndexError:
		print "Packet IP layer not Found"



def plain_sniff():
	sniff(iface=interface,prn=read_packet,filter="dst port 45001")	
plain_sniff()
