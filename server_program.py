import atozmod
import os
import sys
from scapy.all import *
import socket
import time
import random
import netifaces,commands

#Global variables

interface="eth0"
server_ip_address=atozmod.get_ip_address()
server_mac_address=atozmod.get_mac_address()

# For Loopback Address 
# conf.L3socket = L3RawSocket For localhost



#Functions For ARP Module

def send_notification(ip,mac,message):
	message="|Message|"+message
	print "Message Has been sending ::",message
	nlayer=IP(src=server_ip_address,dst=ip)	
	dllayer=Ether(dst=mac,src=server_mac_address,type=0x800)
	tlayer=UDP(sport=46000,dport=45001)
	packet=dllayer/nlayer/tlayer/Raw(message)
	sendp(packet)
	

def verify_client_request(register_ip,register_mac,data_ip,data_mac):
	print register_ip,data_ip,register_mac,data_mac		
	key_pairs=dict()
	try:
		print "Client IP and Mac Address are checking ..."
		open_key_file=open("server_keys","r")
		keys_data=open_key_file.read().split("\n")
		for key_pair in keys_data:
			try:
				key_pair_split=key_pair.split("|")
				print key_pair_split[0]
				key_pairs[key_pair_split[0]]=key_pair_split[1]
			except IndexError:
				print "index error in server_key_file"
		
		if register_mac not in key_pairs.keys():
			append_file=open("server_keys","a")
			append_file.write(register_mac+"|"+send_key_to_client(register_ip,register_mac)+"\n")
		else:
			#Checking how many times client try to register in the server
			message="Key already Granted to the Client.Please contact Administrator@@"
			send_notification(register_ip,register_mac,message)
			
	except IOError:
		print "Occured"
		open_block_list=open("server_blocks","a")
		open_block_list.write("register_mac"+"\n")

def check_client_status(client_ip,client_mac):
	blocked_list=dict()
	try:
	
		open_block_list=open("server_blocks","r")
		read_file=open_block_list.read().split("\n")
		read_file=read_file[:len(read_file)-1]
		for entry in read_file:			
			entry=entry.split(" ")
			blocked_list[entry[0]]=entry[1]+" "+entry[2]
		if client_mac not in blocked_list.keys():
			write_to_list=open("server_blocks","a")
			write_to_list.write(client_mac+" 1 "+"unblock\n")
		else:		
			client_status="unblock"
			count=int(blocked_list[client_mac].split(" ")[0])
			count=count+1
			if count>=3:
				client_status="block"
			if client_status=="block":				
				blocked_list[client_mac]=str(count)+" "+"block"
				message="Your Mac Address has been Blocked Please Contact System Administrator"
				send_notification(client_ip,client_mac,message)
			else:
				blocked_list[client_mac]=str(count)+" "+"unblock"
			write_to_list=open("server_blocks","w")
			for entry in blocked_list:
				write_to_list.write(entry+" "+blocked_list[entry]+"\n")

			
	except IOError:
		print "File Not found"
		print "File Created"
		write_to_list=open("server_blocks","w")
		write_to_list.write(client_mac+" 1 "+"unblock\n")
			
	
	

def verify_client_key(register_ip,register_mac,client_key):
	key_pairs=dict()
	try:
		
		open_key_file=open("server_keys","r")
		keys_data=open_key_file.read().split("\n")
		keys_data=keys_data[:len(keys_data)-1]
		
		for key_pair in keys_data:
			try:
				key_pair_split=key_pair.split("|")
				key_pairs[key_pair_split[0]]=key_pair_split[1]
			except KeyError:
				print "Key Error while Adding key pairs to dictionary"
			except IndexError:
				print "Index Error while Adding key pairs to dictionary"
		print key_pairs.keys(),register_mac
		if register_mac in key_pairs.keys():		
			if key_pairs[register_mac]==client_key:
				create_update_entry(register_ip,register_mac)	
				print "working"			
			else:
				print "User Entered Wrong Password Checking User Status"
				check_client_status(register_ip,register_mac)

		
	except IOError:		
		open_block_list=open("server_blocks","a")
		open_block_list.write("register_mac"+"\n")

def verify_client_ip_mac(register_ip,register_mac,data_ip,data_mac):
	if (register_ip==data_ip and register_mac==data_mac):
		return True
	else:
		return False
	


def send_key_to_client(ip,mac):
	key=""
	for i in range(10):
		key=key+chr(random.randint(97,122))
	print key
	nlayer=IP(src=server_ip_address,dst=ip)
	message="|New_Key|"+key
	dllayer=Ether(dst=mac,src=server_mac_address,type=0x800)
	tlayer=UDP(sport=46000,dport=45001)
	packet=dllayer/nlayer/tlayer/Raw(message)
	sendp(packet,iface="eth0")
	print "Sended key :" +key
	return key

def send_update_message(ip,mac):
	dlayer=Ether(dst="ff:ff:ff:ff:ff:ff",src=server_mac_address,type=0x800)
	message="|Update_Message|"+ip+" "+mac+"\n"
	nlayer=IP(src=server_ip_address,dst="255.255.255.0")
	tlayer=UDP(sport=46000,dport=45001)
	packet=dlayer/nlayer/tlayer/Raw(message)
	sendp(packet,iface="eth0")	



def create_update_entry(ip,mac):	
	ip_mac_pairs_payload=""
	ip_mac_pairs=dict()
	open_file=open("hosts","r")	
	ip_mac_array=open_file.readlines()
	for i in ip_mac_array:
		ip_mac=i.split("\n")[0].split(" ")
		ip_mac_pairs[ip_mac[0]]=ip_mac[1]
	print ip_mac_pairs
	open_file.close()
	if ip not in ip_mac_pairs.keys():
		message= "Successfully registered in server"
		print message
		send_notification(ip,mac,message)
		os.system("sudo arp -s "+ip+" "+mac)	
		ip_mac_pairs[ip]=mac
	else:
		if ip_mac_pairs[ip]!=mac:
			ip_mac_pairs[ip]=mac
		else:
			message="Client already registered in server"
			send_notification(ip,mac,message)
			
	open_file=open("hosts","w")
	for i in ip_mac_pairs.keys():		
		open_file.write(i+" "+ip_mac_pairs[i]+"\n")
		sys.stdout.flush()
	ip_mac_pairs_payload="|Response_Message|"
	for i in ip_mac_pairs.keys():		
		if i!=ip:
			ip_mac_pairs_payload += i+" "+ip_mac_pairs[i]+"\n"
   # Send Update Message & Response Message
	send_update_message(ip,mac)	
	send_response_message(ip,mac,ip_mac_pairs_payload)
	
	



	
def send_response_message(ip,mac,ip_mac_pairs_payload):
	print ip,mac,ip_mac_pairs_payload
	nl=IP(src=server_ip_address,dst=ip)
	dll=Ether(dst=mac,src=server_mac_address)
	udp=UDP(dport=45001,sport=46000)
	response_packet=nl/udp/ip_mac_pairs_payload
	send(response_packet)



def read_packet(pkt):
	register_ip=pkt[IP].src	
	register_mac=pkt.src
	print register_ip,register_mac
	data=pkt[UDP].load	
	data_split=data.split("|")
	print data_split	
	if data_split[1]=="Request_Key":
		data_ip=data_split[2]
		data_mac=data_split[3]
		verify_result=verify_client_ip_mac(register_ip,register_mac,data_ip,data_mac)
		if verify_result==True:					
			verify_client_request(register_ip,register_mac,data_ip,data_mac)
		else:
			print "MAC Address spoofing identified "
			print "Details are "+register_ip+" "+register_mac+" "+data_ip+" "+data_mac
		
	try:
		if data_split[1]=="Key":
			
			client_key=data_split[2]
			verify_client_key(register_ip,register_mac,client_key)
	except KeyError:
		print "Splitting Error in Key checking"
		
		
		#create_update_entry(register_ip,register_mac)



def plain_sniff():
	sniff(iface=interface,prn=read_packet,filter="dst port 46001")	
plain_sniff()
	
