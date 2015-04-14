######################################################################################
# Custom Developed Module for Arp Spoofing Prevention Method.
# It access host IP and MAC address through linux system commands.
# Developed By piratesecurity.
######################################################################################

import commands
import netifaces
#Global Variables
interface="eth0"

def get_ip_address():	
	try:
		words = commands.getoutput("sudo ifconfig " + interface).split()	
		if "HWaddr" in words:
			return words[ words.index("HWaddr") + 3 ].split(":")[1]
	except:
		print "Unable Get MAC Address of the Device."
		exit(1)
		

def get_mac_address():
	try:
		words = commands.getoutput("sudo ifconfig " + interface).split()
		if "HWaddr" in words:
			return words[ words.index("HWaddr") + 1 ]
	except:
		print "Unable Get MAC Address of the Device."
		exit(1)
		
