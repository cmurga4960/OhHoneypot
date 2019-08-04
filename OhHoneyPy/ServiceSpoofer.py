import os
import rstr
import time
import threading
import traceback
from scapy.all import *
from ScapyServer import ScapyServer
from SessionManager import SessionManager
from colorama import Fore, Back, Style

# Interacts with a client by going through the three-way handshake.
# Shuts down the connection immediately after the connection has been established.
# Akaljed Dec 2010, https://akaljed.wordpress.com/2010/12/12/scapy-as-webserver/

'''
Use expression from /usr/share/nmap/nmap-service-probes
For example from nmap-service-probes file....
--------------------------------------------------------------------------------------------------------------------
# NoMachine Network Server
# Announce client version 5.6.7 (could be anything)
Probe TCP NoMachine q|NXSH-5.6.7\n|
ports 4000
rarity 9

match nomachine-nx m|^NXD-([\d.]+)\n| p/NoMachine NX Server remote desktop/ v/$1/ cpe:/a:nomachine:nx_server:$1/
--------------------------------------------------------------------------------------------------------------------
set experssion = r'^NXD-([\d.]+)\n'

- Note, not all services will work due to the limitations of rstr.xeger and nmaps usage of perl's 'i' and 's' options
- Avoid services that have "|s" or "|i" in them.
- Nmap rules that use the response to print the version may also lead to warnings or bad results.
- Expressions with non-zero bytes may be ify?

See notes at the bottom for more details.
'''

#EXTRAS
color = True
tcp_color = Fore.LIGHTMAGENTA_EX if color else ''
udp_color = Fore.LIGHTBLUE_EX if color else ''
reset_color = Style.RESET_ALL if color else ''
red = Fore.RED if color else ''
green = Fore.GREEN if color else ''
#EXTRAS


class ServiceSpoofer(ScapyServer):

	def __init__(self, interfaces, service_list, os_spoofer=None):
		if type(service_list) == str:
			service_list = [service_list]
		# service_list = [ "port,tcp/udp,id", "", ... ]
		self.interfaces = interfaces
		self.os_spoofer = os_spoofer

		self.tcp_ports = ""
		self.udp_ports = ""
		self.tcp_port_list = []
		self.udp_port_list = []
		self.services = []
		self.port_mapper = {}
		for service_data in service_list:
			data = service_data.split(',')
			s = Service(data[0], data[2], True if data[1].lower() == 'tcp' else False)
			self.services.append(s)
			self.port_mapper[str(s.port)+str(s.tcp)] = self.services[-1]  # for Duel sniff version
			if s.tcp:
				if self.tcp_ports:
					self.tcp_ports += " or "
				self.tcp_ports += "port " + str(s.port)
			else:
				if self.udp_ports:
					self.udp_ports += " or "
				self.udp_ports += "port " + str(s.port)

		self.thread = Thread(target=self._start, daemon=True)
		self.tcp_thread = Thread(target=self._startTCP, daemon=True)
		self.udp_thread = Thread(target=self._startUDP, daemon=True)
		self.stopper = True

		self.ip_addrs = []
		self.ip_filter = ""
		for interface in self.interfaces:
			addr = SessionManager.getIpAddress(interface)
			self.ip_addrs.append(addr)
			if self.ip_filter:
				self.ip_filter += " or "
			self.ip_filter += "dst host " + addr

	def start(self):
		self.stopper = False
		self._startIpTables()
		self.thread.start()

	def stop(self):
		self.stopper = True
		self._stopIpTables()

	# Called as daemon
	def _start(self):
		self._startSniffing()
		while not self.stopper:
			try:
				time.sleep(.75)
			except KeyboardInterrupt:
				break
			except:
				break
		#print(green + "Server Done for "+str(self.port) + reset_color)

	@staticmethod
	def find_between(s, first, last):
		try:
			start = s.index(first) + len(first)
			end = s.index(last, start)
			return s[start:end]
		except ValueError:
			return ""

	def _startIpTables(self):
		if SessionManager.getInstance().is_android:
			iptables = '/system/bin/iptables'
		else:
			iptables = 'iptables'
		for service in self.services:
			if service.tcp:
				set_iptable = iptables+' -I OUTPUT -p tcp --tcp-flags RST RST --sport ' + str(service.port) + ' -j DROP'
			elif service.udp:
				set_iptable = iptables+' -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP'
			if not set_iptable[12:] in os.popen(iptables+'-save').read():
				os.system(set_iptable)

	def _stopIpTables(self):
		if SessionManager.getInstance().is_android:
			iptables = '/system/bin/iptables'
		else:
			iptables = 'iptables'
		for service in self.services:
			if service.tcp:
				set_iptable = iptables+' -D OUTPUT -p tcp --tcp-flags RST RST --sport ' + str(service.port) + ' -j DROP'
			elif service.udp:
				set_iptable = iptables+' -D OUTPUT -p icmp --icmp-type destination-unreachable -j DROP'
			os.system(set_iptable)

	def _endCondition(self, packet):
		return self.stopper

	def _startSniffing(self):
		# Duel sniffer version
		# TODO upon prn method, a blank line prints - stop this
		if self.tcp_ports:
			self.tcp_thread.start()
		if self.udp_ports:
			self.udp_thread.start()

		# For multi sniff version: for each service, sniff(prp=service.callback)
		# this may lead to strain on resources though. Would need to test

	def _startTCP(self):
		for service in self.services:
			print(tcp_color + "Service: " + str(service) + reset_color)
		print(tcp_color + 'tcp server start' + reset_color)
		sniff(filter="tcp[tcpflags] & tcp-syn != 0 and (" + self.ip_filter + ") and (" + self.tcp_ports + ")",
			  prn=self.answerTCP, iface=self.interfaces, stop_filter=self._endCondition)
		print(tcp_color + 'tcp server stopped' + reset_color, end="")

	def _startUDP(self):
		for service in self.services:
			print(udp_color + "Service: " + str(service) + reset_color)
		print(udp_color + 'udp server start' + reset_color)
		sniff(filter="udp and (" + self.ip_filter + ") and ("+self.udp_ports+")",
			  prn=self.answerUDP, iface=self.interfaces, stop_filter=self._endCondition)
		print(udp_color + 'udp server stopped' + reset_color, end="")

	def answerTCP(self, packet):
		try:
			#print(tcp_color + 'New tcp client:')
			#packet.show()
			#print(reset_color, end="")

			dport = packet.sport
			sport = packet.dport
			SeqNr = packet.seq
			AckNr = packet.seq+1
			my_mac = packet['Ether'].dst
			victim_mac = packet['Ether'].src
			victim_ip = packet['IP'].src
			my_ip = packet['IP'].dst
			service = self.port_mapper[str(sport)+"True"]

			# send syn ack
			ip = IP(src=my_ip, dst=victim_ip)
			ether = Ether(src=my_mac, dst=victim_mac, type=0x800)
			tcp_synack = TCP(sport=sport, dport=dport, flags="SA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])
			handshake = ip/tcp_synack
			if SessionManager.getInstance().is_android:
				handshake = ether/handshake
			#print(tcp_color+"sending synack", end="")
			if self.os_spoofer:
				handshake = self.os_spoofer.handleTCP(packet, handshake)
				if not handshake:
					return
			if SessionManager.getInstance().is_android:
				ANSWER = srp1(handshake, timeout=8, iface=self.interfaces[0])
			else:
				ANSWER = sr1(handshake, timeout=8, verbose=0)
			#print("\ngot it"+reset_color)
			if not ANSWER:
				#print(red + "TIMEOUT on syn ack" + reset_color)
				return ""

			# Capture next TCP packet if the client talks first
			#GEThttp = sniff(filter="tcp and src host "+str(victim_ip)+" and port "+str(server_port),count=1)
			#GEThttp = GEThttp[0]
			#AckNr = AckNr+len(GEThttp['Raw'].load)

			# send psh ack (main tcp packet)
			SeqNr += 1
			#payload="HTTP/1.1 200 OK\x0d\x0aDate: Wed, 29 Sep 2010 20:19:05 GMT\x0d\x0aServer: Testserver\x0d\x0aConnection: Keep-Alive\x0d\x0aContent-Type: text/html; charset=UTF-8\x0d\x0aContent-Length: 291\x0d\x0a\x0d\x0a<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\"><html><head><title>Testserver</title></head><body bgcolor=\"black\" text=\"white\" link=\"blue\" vlink=\"purple\" alink=\"red\"><p><font face=\"Courier\" color=\"blue\">-Welcome to test server-------------------------------</font></p></body></html>"
			payload = service.genRegexString()
			tcp_pshack = TCP(sport=sport, dport=dport, flags="PA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])
			tcp_main = ip/tcp_pshack/payload
			if SessionManager.getInstance().is_android:
				tcp_main = ether/tcp_main
			#print(tcp_color, end="")

			if SessionManager.getInstance().is_android:
				ACKDATA = srp1(tcp_main, timeout=5, iface=self.interfaces[0])
			else:
				ACKDATA = sr1(tcp_main, timeout=5, verbose=0)
			#print(reset_color, end="")
			if not ACKDATA:
				#print(red + "TIMEOUT on ack data" + reset_color)
				return ""

			# send fin
			SeqNr = ACKDATA.ack
			tcp_fin_ack = TCP(sport=sport, dport=dport, flags="FA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])
			#print(tcp_color, end="")
			goodbye = ether/ip/tcp_fin_ack
			if SessionManager.getInstance().is_android:
				sendp(goodbye, iface=self.interfaces[0])
			else:
				send(goodbye, verbose=0)
			#print(tcp_color+'tcp client done' + reset_color)
		except Exception as e:
			print("TCP ERR",e)
			traceback.print_exec()
		return ""

	def answerUDP(self, packet):
		#print(udp_color + 'New udp client:')
		#packet.summary()
		#print(reset_color, end="")

		dst_port = packet.sport
		src_port = packet.dport
		victim_ip = packet['IP'].src
		my_ip = packet['IP'].dst
		service = self.port_mapper(str(src_port)+"False")

		ip = IP(src=my_ip, dst=victim_ip)
		udp = UDP(sport=src_port, dport=dst_port)
		payload = service.genRegexString()
		udp_main = ip/udp/payload
		#print(udp_color, end="")
		if SessionManager.getInstance().is_android:
			ether = Ether(src=packet['Ether'].dst, dst=packet['Ether'].src, type=0x800)
			sendo(ether/udp_main, iface=self.interfaces[0])
		else:
			send(udp_main)
		#print(udp_color + 'udp client done' + reset_color)
		return ""


class Service:

	def __init__(self, port, identifier, tcp_udp=True):
		self.port = port
		self.identifier = identifier
		self.tcp = bool(tcp_udp)
		self.udp = not self.tcp
		self.regex_expression, self.service_name = Service.findExpression(self.identifier)
		temp = self.service_name.split()[3:]
		self.service_name = " ".join(temp)
		#for t in temp:
		#	self.service_name += t+" "
		if not self.regex_expression:
			raise Exception("Invalid service identifier")

	def genRegexString(self):
		return rstr.xeger(self.regex_expression)

	@staticmethod
	def findExpression(service_id):
		# TODO update after cleaning nmap_results_good_lines.txt
		# Usage: service_id = (string) name of service - returns first match
		#   or   service_id = (int) nth service in nmap-service-probes file
		service_name = ''
		service_number = 0
		try:
			service_number = int(service_id)
		except:
			service_name = service_id

		path = "OhHoneypot/OhHoneyPy/" if SessionManager.is_android else ''
		good_services = open(path+'nmap_results_good_lines.txt', 'r').read().split('\n')
		if service_name:
			for service in good_services:
				if service:
					org_port, good, line_number, rule, regex, result = service.split(';;;')
					if service_name in result or service_name in rule[:20]:  # TODO tweak for better ux
						#print(service)
						return regex, result
		else:
			try:
				org_port, good, line_number, rule, regex, result = good_services[service_number].split(';;;')
				return regex, result
			except:
				return ''
		# TODO test if need to convert regex to raw string (r'') format

	def __str__(self):
		return self.service_name +" ("+str(self.port)+"/"+('tcp' if self.tcp else 'udp')+")"


def findnth(haystack, needle, n):
	parts = haystack.split(needle, n+1)
	if len(parts) <= n+1:
		return -1
	return len(haystack)-len(parts[-1])-len(needle)


if __name__ == '__main__':
	#'''
	# Nmap Test Suite
	''' batch method
	import paramiko
	i_port = 20000
	resume_port = i_port
	eth = 'eth0'
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect('10.0.0.8', 22, 'root', 'toor')
	time.sleep(3)
	services = open('/usr/share/nmap/nmap-service-probes', 'r')
	lines = services.read().split('\n')
	services.close()
	results_file_good = '/root/nmap2_results_good.txt'
	results_file_bad = '/root/nmap2_results_bad.txt'
	servers = []
	smallest_port = 700000
	largest_port = 0
	for line in lines:
		if not 'match ' in line:
			continue
		if line[0] == '#':
			continue
		test = line[findnth(line, ' ', 1)+1:]
		delim = test[1]
		service_name = ServiceSpoofer.find_between(test,' ',' ')
		regex = ServiceSpoofer.find_between(test, delim, delim)
		if delim + "i" in line:
			continue
		if delim + "s" in line:
			continue
		#print("test:" + test)
		#print("delim:" + delim)
		#print("regex:" + regex)
		#print("line:" + line)
		#try:
		server = ServiceSpoofer(i_port, eth, expression=regex, service_name=service_name, line=line, regex=regex)
		server.start()
		servers.append(server)
		if i_port < smallest_port:
			smallest_port = i_port
		if i_port > largest_port:
			largest_port = i_port
		i_port += 1

		if len(servers) >= 500:
			print('wait for threads to catch up')
			time.sleep(15) #wait for servers to start
			command = "nmap 10.0.0.9 -T5 -sV --version-all -p " + str(smallest_port) + "-"+\
					  str(largest_port)+" -oN /root/nmap_test2/" + str(smallest_port) + "_"+\
					  str(largest_port) + ".txt"
			print(command, "... make take a while...")
			stdin, stdout, stderr = ssh.exec_command(command)
			results = stdout.read()
			results = results.decode('utf-8')
			print('nmap done')
			for server in servers:
				for line in results.split('\n'):
					if str(server.port)+"/tcp " in line:
						if "?" in line:
							w = open(results_file_bad, 'a+')
							w.write(str(server.port) + ",,,unrecognized,,,"+ server.service_name +
									",,," + server.line + ",,," + server.regex + "\n")
							w.close()
						elif str(server.port)+"/tcp closed" in results:
							w = open(results_file_bad, 'a+')
							w.write(str(server.port) + ",,,closed,,," + server.service_name +
									",,," + server.line + ",,," + server.regex + "\n")
							w.close()
						elif 'tcpwrapped' in results:
							w = open(results_file_bad, 'a+')
							w.write(str(server.port) + ",,,tcpwrapped,,," + server.service_name +
									",,," + server.line + ",,," + server.regex + "\n")
							w.close()
						else:
							w = open(results_file_good, 'a+')
							w.write(str(server.port) + ",,,good,,," + server.service_name +
									",,," + server.line + ",,," + server.regex + "\n")
							w.close()
				server.stop()
			servers.clear()

			smallest_port = 700000
			largest_port = 0
			print('wait for threads to die')
			time.sleep(30)
			print('next round...')
		#except Exception as e:
		#	print(e)
		#	w = open('/root/nmap2_err.txt', 'a+')
		#	w.write(str(i_port) + "," + str(e) + "," + line + ",,," + regex + "\n")
		#	w.close()

	print(green + "Done Done " +str(len(servers))+ reset_color)
	while 1:
		try:
			time.sleep(1)
		except Exception:
			break
	for s in servers:
		s.close()
	# '''

	''' slow way
	# Nmap Test Suite
	import paramiko
	i_port = 30000 + 0
	#tcp ports #8467  # 4306  # 3837  #2556
	eth = 'eth0'
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect('10.0.0.8', 22, 'root', 'toor')
	time.sleep(3)
	services = open('/usr/share/nmap/nmap-service-probes', 'r')
	lines = services.read().split('\n')
	services.close()
	results_file_good = '/root/udp_good.txt'
	results_file_bad = '/root/udp_bad.txt'
	line_number = 0
	resume_line = 0
	# tcp lines #15566  #6382  # 5551 #3768

	for line in lines:
		line_number += 1
		if line_number < resume_line:
			continue
		if not 'match ' in line:
			continue
		if '#' == line[0]:
			continue
		test = line[findnth(line, ' ', 1)+1:]
		delim = test[1]
		regex = ServiceSpoofer.find_between(test, delim, delim)
		if delim + "i" in line:
			continue
		if delim + "s" in line:
			continue
		try:
			server = ServiceSpoofer(i_port, eth, expression=regex, tcp=False)
			server.start()
			time.sleep(1.5)
			command = "nmap 10.0.0.9 -T5 -Pn -sV --version-all -p "+str(i_port)+" -oN /root/nmap_udp/"+str(i_port)+".txt"
			print(command)
			print("Line#", line_number, "expecting:", ServiceSpoofer.find_between(line, ' ', ' '))
			stdin, stdout, stderr = ssh.exec_command(command)
			results = stdout.read()
			results = results.decode('utf-8')
			main_result = ''
			for data in results.split('\n'):
				if str(i_port)+"/tcp" in data:
					main_result = data
					break
			server.stop()
			dst = ""
			if 'unrecognized despite returning data' in results:
				w = open(results_file_bad, 'a+')
				w.write(str(i_port)+";;;unrecognized;;;"+str(line_number)+";;;"+line+";;;"+regex+";;;"+main_result+"\n")
				w.close()
				dst = 'unrecognized'
			elif 'tcp closed' in results:
				w = open(results_file_bad, 'a+')
				w.write(str(i_port)+";;;closed;;;"+str(line_number)+";;;"+line+";;;"+regex+";;;"+main_result+"\n")
				w.close()
				dst = 'closed'
			elif 'tcpwrapped' in results:
				w = open(results_file_bad, 'a+')
				w.write(str(i_port)+";;;tcpwrapped;;;"+str(line_number)+";;;"+line+";;;"+regex+";;;"+main_result+"\n")
				w.close()
				dst = 'tcpwrapped'
			elif 'tcp filtered' in results:
				w = open(results_file_bad, 'a+')
				w.write(str(i_port)+";;;filtered;;;"+str(line_number)+";;;"+line+";;;"+regex+";;;"+main_result+"\n")
				w.close()
				dst = 'filtered'
			else:
				w = open(results_file_good, 'a+')
				w.write(str(i_port)+";;;good;;;"+str(line_number)+";;;"+line+";;;"+regex+";;;"+main_result+"\n")
				w.close()
				dst = 'good'

			print('result was '+dst, 'got', main_result)
			stdin, stdout, stderr = ssh.exec_command("cp /root/nmap_udp/" + str(i_port) + ".txt /root/nmap_udp/" + dst)
			stdout.read()
			i_port += 1
			time.sleep(2)
		except ValueError as ve:
			print(ve)
			print("Resume at", line_number, i_port)
			break
		except Exception as e:
			print(e)
			print("Resume at", line_number, i_port)
			w = open('/root/udp_err.txt', 'a+')
			w.write(str(i_port)+";;;"+str(e)+";;;"+str(line_number)+";;;"+line+";;;"+regex+";;;"+main_result+"\n")
			w.close()

	print(green + "Done Done" + reset_color)
	# '''

	# '''
	# Normal operation
	servers = [ServiceSpoofer(80, 'eth0', service_number=910, tcp=False)]
	for server in servers:
		server.start()
	print(reset_color+'Servers started')

	# Wait till killed
	while 1:
		try:
			time.sleep(1)
		except KeyboardInterrupt:
			break
		except:
			break
	for server in servers:
		server.stop()
	print(green + "Done Done" + reset_color)
	#'''

'''
NOTES
- If nmap flags as tcpwrapped service, its likely you are not responding (or responding incorrectly) after handshake.  E.g. bad ack or seq #
- If nmap does not recognize the service, you may need to set --version-intensity 9  or --version-all   (default is 7)
- Nmap skips ports 9100-9107 for -sV scan, even upon adding "-p 9100".  Use --allports  to bypass this.  
- Note, not all services will work due to the limitations of rstr.xeger and nmaps usage of perl's 'i' and 's' options.  
  In general, dynamically generating string that fit regex is a hard problem
- Nmap -O (OS scan) and -sU (UDP scan) options require root (at least on Android's Termux).
- The -sV option will not send UDP packet at all unless -sU is specified. Jeez nmap, letting me down here xD


LINKS
- Scapy send vs sendp  http://abunchofbaloney.blogspot.com/2014/09/scapy-send-vs-sendp.html\
- Nmap version options   https://nmap.org/book/man-version-detection.html
- Nmap service detction file format  https://nmap.org/book/vscan-fileformat.html#vscan-fileformat-example
- Nmap os dection workings  https://nmap.org/book/osdetect-methods.html
- Linux routing  https://www.cyberciti.biz/faq/linux-route-add/
- BPF syntax http://biot.com/capstats/bpf.html
'''

