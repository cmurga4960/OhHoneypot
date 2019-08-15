#  Ah, nothing like starting new feature.  Alonsly! (-the4960 7/25/19 4:38 am)
from scapy.all import *
import threading
import time
import os
import traceback
from Abstract.ScapyServer import ScapyServer
from Abstract.Publisher import Publisher
from SessionManager import SessionManager, Fingerprint
from Event import *
from colorama import Fore, Back, Style
import codecs

# Should only need on instance
from scapy.layers.inet import ICMP, IP, UDP, IPerror, UDPerror, TCP, Ether

# TODO add way for OsSpoofer to run just enough for IDS to run
# maybe put if's around self.personality_fingerprint

class OsSpoofer(ScapyServer, Publisher):
    def __init__(self, interfaces, os_fingerprint_number_or_number, ignore_ports=[], services=[]):
        super(OsSpoofer, self).__init__()
        if type(services) == str:
            services = [services]
        self.interfaces = interfaces
        self.ignore_ports = ignore_ports
        self.cache = {}

        # self.os_fingerprint_number = os_fingerprint_number
        self.personality_fingerprint = Fingerprint(fingerprint_id=os_fingerprint_number_or_number)
        SessionManager.getInstance(self.personality_fingerprint)
        self.stopper = True
        self.thread = threading.Thread(target=self._start, daemon=True)
        self.nmap_session = {}
        self.services_string = services
        self.ip_addrs = []
        self.ip_filter = ""
        for interface in self.interfaces:
            addr = SessionManager.getIpAddress(interface)
            self.ip_addrs.append(addr)
            if self.ip_filter:
                self.ip_filter += " or "
            self.ip_filter += "dst host " + addr

        self.rules = ['OUTPUT -p icmp -m icmp --icmp-type 0 -j DROP',
                      'OUTPUT -p icmp -m icmp --icmp-type 14 -j DROP',
                      'OUTPUT -p icmp -m icmp --icmp-type 3 -j DROP']

        # TODO improve port filter logic
        if self.ignore_ports:
            self.ip_filter = "("+self.ip_filter+") and ("
            for port in self.ignore_ports:
                self.ip_filter += "not (dst port "+str(port)+" or src port "+str(port)+") and "
                self.rules.append('OUTPUT -p tcp -m tcp --dport '+str(port)+' -j ACCEPT')
                self.rules.append('OUTPUT -p tcp -m tcp --sport '+str(port)+' -j ACCEPT')
            self.ip_filter = self.ip_filter[:-4] + ")"
        self.rules.append('OUTPUT -p tcp -j DROP')  # TODO scope down tcp

        self.open_ports = []  # TODO delete and use open_tcp/udp
        self.open_tcp = []
        self.open_udp = []
        for service in services:
            self.open_ports.append(service.split(",")[0])
            if ',tcp,' in service:
                self.open_tcp.append(self.open_ports[-1])
            else:
                self.open_udp.append(self.open_ports[-1])

        self.calculateCache()

        # adding to fingerprint to handle seq ommited values
        for attribute in ["ii", "ti", "ci"]:
            if attribute not in self.personality_fingerprint['seq']:
                self.personality_fingerprint['seq'][attribute] = ""

        self.udp_payloads = {}
        # self.udp_payloads[port] = array of potential payloads
        self.initUDPPayloads()

    def initUDPPayloads(self):
        lines = open('nmap-payloads', 'r').read().split('\n')
        current_ports = []
        current_payload = ""
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("source "):
                continue
            if line.startswith("udp "):
                # submit last udp port
                if current_ports:
                    for port in current_ports:
                        port_num = int(port)
                        if port_num not in self.udp_payloads:
                            self.udp_payloads[port_num] = []
                        self.udp_payloads[port_num].append(current_payload.lower())
                    current_payload = ""
                # start new port
                data = line.split()
                current_ports = data[1].split(",")
                if len(data) > 2:
                    temp_payload = " ".join(data[2:])
                    current_payload += temp_payload[temp_payload.index('"')+1:temp_payload.rindex('"')]
            if line.startswith('"') and current_ports:
                current_payload += line[line.index('"')+1:line.rindex('"')]

        if current_ports:
            for port in current_ports:
                port_num = int(port)
                if port_num not in self.udp_payloads:
                    self.udp_payloads[port_num] = []
                self.udp_payloads[port_num].append(current_payload)

        # for port in self.udp_payloads:
        #    print(port, type(port), self.udp_payloads[port])


    def calculateCache(self):
        o_list = []
        for test in self.personality_fingerprint:
            try:
                o_list.append(self.personality_fingerprint[test]['o'])
            except:
                pass
        for o_num in self.personality_fingerprint.ops:
            o_list.append(self.personality_fingerprint.ops[o_num])

        for o in o_list:
            options = []
            copy_buffer = ""
            waiting_letter = ""
            letter = ""
            for i in range(len(o)):
                letter = o[i]
                # COpy me to after loop
                if waiting_letter and (letter == 'l' or letter == 'n' or letter == 'm' or letter == 'w' or
                                       letter == 't' or letter == 's'):
                    if waiting_letter == "m":
                        value = int(copy_buffer, 16)
                        options.append(('MSS', value))
                    elif waiting_letter == "w":
                        value = int(copy_buffer, 16)
                        options.append(('WScale', value))
                    elif waiting_letter == "t":
                        # TODO This will require more than usual testing
                        value1 = int(copy_buffer[0], 16)
                        value2 = int(copy_buffer[1], 16)
                        options.append(('Timestamp', (value1, value2)))
                    waiting_letter = ""
                    copy_buffer = ""
                # Copy me to after loop
                if letter == 'l':
                    options.append(('EOL', None))
                elif letter == 'n':
                    options.append(('NOP', None))
                elif letter == 's':
                    options.append(('SAckOK', b''))  # TODO test
                elif letter == 'm' or letter == 'w' or letter == 't':
                    waiting_letter = letter
                elif letter == "|":
                    break  # TODO?
                else:
                    copy_buffer += letter
            # COpyied me to after loop
            if waiting_letter:
                if waiting_letter == "m":
                    value = int(copy_buffer, 16)
                    options.append(('MSS', value))
                if waiting_letter == "w":
                    value = int(copy_buffer, 16)
                    options.append(('WScale', value))
                if waiting_letter == "t":
                    # TODO This will require more than usual testing
                    value1 = int(copy_buffer[0], 16)
                    value2 = int(copy_buffer[1], 16)
                    options.append(('Timestamp', (value1, value2)))
            # Copyied me to after loop
            self.cache[o] = options

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
                time.sleep(1)
            except Exception as e:
                print('_start loop err', e)
                break
        print('OsSpoofer thread stopped')

    def _endCondition(self, packet):
        return self.stopper

    def _startIpTables(self):
        if SessionManager.getInstance().is_android:
            iptables = '/system/bin/iptables'
        else:
            iptables = 'iptables'
        for rule in self.rules:
            if rule not in os.popen(iptables+'-save').read():
                os.system(iptables+" -A " + rule)

    def _stopIpTables(self):
        if SessionManager.getInstance().is_android:
            iptables = '/system/bin/iptables'
        else:
            iptables = 'iptables'
        for rule in self.rules:
            if rule in os.popen(iptables+'-save').read():  # Need this?
                os.system(iptables+" -D " + rule)

    def _startSniffing(self):
        icmp_filter = "icmp"
        tcp_filter = "tcp"
        udp_filter = "udp"
        main_filter = "(" + tcp_filter + " or " + udp_filter + " or " + icmp_filter + ") and ("+self.ip_filter+")"
        print(Fore.YELLOW + main_filter + Style.RESET_ALL)
        sniff(filter=main_filter, prn=self._handleIncoming, stop_filter=self._endCondition, iface=self.interfaces)
        # NOTE: sniffing listens for all traffic concerning the host minus any ignore ports
        #       packets from ServiceSpoofer ports are received twice, but handled in the logic

    def _handleIncoming(self, packet):
        try:
            packet['ICMP']
            self._handleICMP(packet)
        except:
            pass
        try:
            packet['TCP']
            self.handleTCP(packet)
        except:
            pass
        try:
            packet['UDP']
            self.handleUDP(packet)
        except:
            pass

    def _handleICMP(self, packet):
        '''
        - The first one has the ip.df bit set, tos =0, a code 9 - even tho
        it should be zero, the seq#=295, a random ip.id and icmp req id, and 120 bytes of 0x00 for payload

        -Second is similar, except tos =4, code=0, 150 bytes sent, icmp id and seq nums are +1

        -TCP probes are sent right after to check ip id seq test (ss)


        ie = icmp echo test
        ie.r = responded
        ie.dfi = dont frag icmp; N=neither ping responses have the DF bit set; S=both responses echo the DF value
                 Y=both the response DF bits are set; O=both responses have the DF bit toggled
        ie.t = TTL
        ie.cd = Depend on ICMP echo reply code
                if both codes = 0, z
                if both codes = the same as in the corresponding probe, s
                if both use same non-zero number, <NN>  -- dont think this ever occurs in the db...
                else, o

        seq.ss = shared sequence ip.id
                if id values are sequential, s
                o if not
        '''
        #print("RECIVED ICMP:", packet.summary())

        if 'r' in self.personality_fingerprint.ie and self.personality_fingerprint.ie['r'] == 'n':
            # Do not respond trololol
            return

        dst_ip = packet['IP'].src
        my_ip = packet['IP'].dst
        response = IP(src=my_ip, dst=dst_ip)/ \
                   ICMP(type=0, id=packet['ICMP'].id, seq=packet['ICMP'].seq)
        try:
            response = response /Raw(load=packet['Raw'].load)
        except IndexError:
            pass

        # Its show time
        try:
            # echo request
            if packet['ICMP'].type == 8:
                if packet['ICMP'].seq == 0:
                    #print('case: icmp seq 0')
                    # is this if -Pn not set?
                    pass

                elif packet['ICMP'].seq == 295:
                    #print('FIRST ICMP PACKET')
                    self.publish(Event(EventTypes.ICMPScan, dst_ip))
                    if 'dfi' in self.personality_fingerprint.ie:
                        if self.personality_fingerprint.ie['dfi'] == 's':
                            response['IP'].flags = packet['IP'].flags
                        elif self.personality_fingerprint.ie['dfi'] == 'y':
                            response['IP'].flags = 2
                        elif self.personality_fingerprint.ie['dfi'] == 'o':
                            response['IP'].flags = 0  # bit toggled from probe
                        else:  # == N
                            response['IP'].flags = 0

                    if 'cd' in self.personality_fingerprint.ie:
                        if self.personality_fingerprint.ie['cd'] == 'z':
                            response['ICMP'].code = 0
                        elif self.personality_fingerprint.ie['cd'] == 's':
                            response['ICMP'].code = packet['ICMP'].code
                        elif self.personality_fingerprint.ie['cd'] == 'o':
                            # TODO test, this may never happen... not in db?
                            response['ICMP'].code = packet['ICMP'].code+1
                        else:  # == N
                            # TODO test, this may never happen... not in db?
                            response['ICMP'].code = int(self.personality_fingerprint.ie['cd'], 16)

                elif packet['ICMP'].seq == 296:
                    #print('SECOND ICMP PACKET')

                    if 'dfi' in self.personality_fingerprint.ie:
                        if self.personality_fingerprint.ie['dfi'] == 's':
                            response['IP'].flags = packet['IP'].flags
                        elif self.personality_fingerprint.ie['dfi'] == 'y':
                            response['IP'].flags = 2
                        elif self.personality_fingerprint.ie['dfi'] == 'o':
                            response['IP'].flags = 2  # bit toggled from probe
                        else:  # == N
                            response['IP'].flags = 0

                    # Abstract out? for now no
                    if 'cd' in self.personality_fingerprint.ie:
                        if self.personality_fingerprint.ie['cd'] == 'z':
                            response['ICMP'].code = 0
                        elif self.personality_fingerprint.ie['cd'] == 's':
                            response['ICMP'].code = packet['ICMP'].code
                        elif self.personality_fingerprint.ie['cd'] == 'o':
                            #TODO test
                            response['ICMP'].code = packet['ICMP'].code+1
                        else:  # == N
                            # this may never happen...
                            response['ICMP'].code = int(self.personality_fingerprint.ie['cd'],16)
                else:
                    # a real ping
                    self.publish(Event(EventTypes.ICMPHit, dst_ip))
                    # TODO respond?
            # timestamp req
            elif packet['ICMP'].type == 13:
                #print('case: timestamp req')
                response = IP(src=my_ip, dst=dst_ip) /\
                           ICMP(type=14, data=packet['ICMP'].data)  # ts_ori=0, ts_rx=0, ts_tx=0

            if 't' in self.personality_fingerprint.ie:
                session_val = SessionManager.getInstance().getValue(dst_ip, "ie", "t")
                try:
                    ttl = int(session_val, 16)
                except:
                    ttl = session_val
                # TODO nmap expects some values over 0x100, so needs fixing
                # this is to patch an error
                response['IP'].ttl = ttl if ttl <= 255 else 255

            if 'ii' in self.personality_fingerprint.seq:
                ii = SessionManager.getInstance().getValue(dst_ip, "seq", "ii")
                #print("SESSION VAL SS:", ss_id)
                # this is to patch an error
                response['IP'].id = ii

        except Exception as ee:
            print(ee)
            traceback.print_exc()
        #print("SENDING ICMP RESPONSE:", response.summary())
        if SessionManager.getInstance().is_android:
            ether = Ether(src=packet['Ether'].dst, dst=packet['Ether'].src, type=0x800)
            sendp(ether/response, iface=self.interfaces[0])
        else:
            send(response, verbose=0)

    def handleTCP(self, packet, server_packet=None):
        # Ello beasty
        '''
        Probes
            Seq sends out six SYN packets to an open port and collects SYN/ACK packets back:

            Packet #1: window scale (10), NOP, MSS (1460), timestamp (TSval: 0xFFFFFFFF; TSecr: 0), SACK permitted. The window field is 1.

            Packet #2: MSS (1400), window scale (0), SACK permitted, timestamp (TSval: 0xFFFFFFFF; TSecr: 0), EOL. The window field is 63.

            Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP, NOP, window scale (5), NOP, MSS (640). The window field is 4.

            Packet #4: SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 4.

            Packet #5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), window scale (10), EOL. The window field is 16.

            Packet #6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0). The window field is 512.


            ecn = excplicit congestion notification: urgent field value=0xf7f5; ack=0, seq#=random, win size=3, reservedbit=set
                                                     tcp options are wscale(10), nop, mss (1460), sack permitted, nop, nop.
                                                     Sent to open port

            T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window field of 128 to an open port.

            T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a window field of 256 to an open port. The IP DF bit is not set.

            T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.

            T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.

            T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.

            T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 65535 to a closed port. The IP DF bit is not set.

        seq
            seq.gcd = greatest common divisor
            seq.isr =
            seq.sp  =
            seq.ti  =
            seq.ii  =
            seq.ts  =
            seq.ss  =
        ops
            o1-o6
        win
            win.w1-w6 =
        ecn
            ecn.r  =
            ecn.df =
            ecn.t  =
            ecn.tg =
            ecn.w  =
            ecn.o  =
            ecn.cc =
            ecn.q  =
        t2-t7
            t2.df =
            t2.tg =
            t2.rd =
            t2.r  =
            t2.t  =
            t2.w  =
            t2.s  =
            t2.a  =
            t2.f  =
            t2.o  =
            t2.q  =

        '''
        print("IN-TCP:", packet.summary())
        dst_ip = packet['IP'].src
        my_ip = packet['IP'].dst
        dport = packet['TCP'].sport
        sport = packet['TCP'].dport
        SeqNr = packet['TCP'].seq
        AckNr = packet['TCP'].seq + 1
        ip_id = random.randint(1, 5000)

        syn = 0x2
        syn_ack = 0x12
        ack = 0x10
        ack_rst = 0x14
        rst = 0x4

        try:
            # if 'ss' in self.personality_fingerprint.seq:
            # ip_id = SessionManager.getInstance().getValue(dst_ip, 'seq', 'ss')

            response_flag = syn_ack if sport in self.open_ports else ack_rst
            response = IP(src=my_ip, dst=dst_ip, id=ip_id) / \
                       TCP(sport=sport, dport=dport, flags=response_flag, seq=SeqNr, ack=AckNr)
            if server_packet:
                response = server_packet

            t_num = ""
            pac_num = ""
            is_nmap = False
            is_sv = False

            # First define which probe it is
            if packet['TCP'].flags == 0x0:  # null
                print('TCP - T2 probe', bool(server_packet))
                t_num = "t2"

            if packet['TCP'].flags == 0x2b:  # syn,fin,urg,psh
                print('TCP - T3 probe', bool(server_packet))
                t_num = "t3"

            if packet['TCP'].flags == ack and packet['IP'].flags == 2:
                if packet['TCP'].window == 1024:
                    # should be sent to an open port
                    print('TCP - T4 probe', bool(server_packet))
                    t_num = "t4"
                elif packet['TCP'].window == 32768:
                    # should be sent to a closed port
                    print('TCP - T6 probe', bool(server_packet))
                    t_num = "t6"
                else:
                    pass  # ignore???

            if packet['TCP'].flags == 0x29:  # fin,psh,urg
                print('TCP - T7 probe', bool(server_packet))
                t_num = "t7"

            if packet['TCP'].flags == syn and len(packet['TCP'].options) >= 3:
                # seq probes and T5
                options = packet['TCP'].options
                #print(options)
                # May later be elaborated to check the whole option range - not too important
                if packet['TCP'].window == 1 and \
                        (('WScale', 10) == options[0]) and \
                        (('NOP', None) == options[1]):
                    print('packet1', bool(server_packet))
                    if bool(server_packet):
                        # I get this twice for one normal -O scan (no -p option) with one open spoofed service
                        self.publish(Event(EventTypes.OSScan, dst_ip))
                    pac_num = "1"
                    t_num = "t1"
                elif packet['TCP'].window == 63 and \
                        (('WScale', 0) == options[1]):
                    print('packet2', bool(server_packet))
                    pac_num = "2"
                elif packet['TCP'].window == 4 and \
                        (('NOP', None) == options[1]) and \
                        (('NOP', None) == options[2]):
                    print('packet3', bool(server_packet))
                    pac_num = "3"
                elif packet['TCP'].window == 4 and \
                        (('EOL', None) == options[-1]) and \
                        (('WScale', 10) == options[-2]):
                    print('packet4', bool(server_packet))
                    pac_num = "4"
                elif packet['TCP'].window == 16 and \
                        (('EOL', None) == options[-1]) and \
                        (('WScale', 10) == options[-2]):
                    print('packet5', bool(server_packet))
                    pac_num = "5"
                elif packet['TCP'].window == 512 and \
                        (('MSS', 265) == options[0]):
                    print('packet6', bool(server_packet))
                    pac_num = "6"
                elif packet['TCP'].window == 29200 and \
                        (('MSS', 1460) == options[0]) and \
                        (('NOP', None) == options[-2]):
                    print('recon packet', bool(server_packet))
                    #packet.show()
                elif packet['TCP'].window == 31337 and \
                        (('WScale', 10) == options[0]) and \
                        (('NOP', None) == options[1]):
                    print("TCP - T5 probe", bool(server_packet))
                    t_num = "t5"
                elif packet['TCP'].window == 64240 and \
                        (('MSS', 1460) == packet['TCP'].options[0]) and \
                        (('WScale', 8) == packet['TCP'].options[-1]):
                    is_sv = True
                else:
                    print("tbd", bool(server_packet))
                    packet.show()

            # Publish once
            if not bool(server_packet):
                try:
                    if is_sv:
                        self.publish(Event(EventTypes.ServiceVersionScanTCP, dst_ip))
                except:
                    pass
                try:
                    # TODO test if this works when nmap on windows - this one was eyeballed not from docs
                    # and on other ports
                    # May have false positives
                    if packet['TCP'].window == 1024 and \
                            packet['TCP'].options == [('MSS', 1460)] and \
                            packet['IP'].flags == 0:
                        self.publish(Event(EventTypes.TCPScan, dst_ip))
                        is_nmap = True
                except:
                    pass

            # Now start responding/spoofing
            if packet['TCP'].ack == 0 and packet['TCP'].window == 3:
                print('ecn packet', bool(server_packet))
                # packet.show()
                if 'cc' in self.personality_fingerprint.ecn:
                    if 'y' == self.personality_fingerprint.ecn['cc']:
                        response['TCP'].flags = int(response['TCP'].flags) + int('1000000', 2)  # only ecn
                    elif 'n' == self.personality_fingerprint.ecn['cc']:
                        pass  # dont set either bit
                    elif 's' == self.personality_fingerprint.ecn['cc']:
                        response['TCP'].flags = int(response['TCP'].flags) + int('11000000', 2)  # both cwr and ecn
                    elif 'o' == self.personality_fingerprint.ecn['cc']:
                        response['TCP'].flags = int(response['TCP'].flags) + int('10000000', 2)  # only cwr
                t_num = "ecn"
            if t_num:
                if 'r' in self.personality_fingerprint[t_num] and self.personality_fingerprint[t_num]['r'] == 'n':
                    # Do not respond trololol
                    #self.publish(Event(EventTypes.TCPScan, dst_ip))
                    return
                if 'df' in self.personality_fingerprint[t_num]:
                    response['IP'].flags = 2 if self.personality_fingerprint[t_num]['df'] == 'y' else 0
                if 'tg' in self.personality_fingerprint[t_num]:
                    response['IP'].ttl = int(self.personality_fingerprint[t_num]['tg'], 16)
                if 'w' in self.personality_fingerprint[t_num]:  # TODO check
                    #TODO account for 0|fff - start at os 200
                    win_size = self.personality_fingerprint[t_num]['w'].split("|")[0]
                    response['TCP'].window = int(win_size, 16)
                if 's' in self.personality_fingerprint[t_num]:
                    if self.personality_fingerprint[t_num]['s'] == 'z':
                        response['TCP'].seq = 0
                    elif self.personality_fingerprint[t_num]['s'] == 'a':
                        response['TCP'].seq = packet['TCP'].ack
                    elif self.personality_fingerprint[t_num]['s'] == 'a+':
                        response['TCP'].seq = packet['TCP'].ack + 1
                    else:  # other
                        # TODO test
                        response['TCP'].seq = packet['TCP'].ack - 2
                if 'a' in self.personality_fingerprint[t_num]:
                    if self.personality_fingerprint[t_num]['a'] == 'z':
                        response['TCP'].ack = 0
                    elif self.personality_fingerprint[t_num]['a'] == 's':
                        response['TCP'].ack = packet['TCP'].seq
                    elif self.personality_fingerprint[t_num]['a'] == 's+':
                        response['TCP'].ack = packet['TCP'].seq + 1
                    else:  # other
                        # TODO test
                        response['TCP'].ack = packet['TCP'].seq - 2
                if 'f' in self.personality_fingerprint[t_num]:
                    flags = 0
                    if "e" in self.personality_fingerprint[t_num]['f']:
                        flags += 64
                    if "u" in self.personality_fingerprint[t_num]['f']:
                        flags += 32
                    if "a" in self.personality_fingerprint[t_num]['f']:
                        flags += 16
                    if "p" in self.personality_fingerprint[t_num]['f']:
                        flags += 8
                    if "r" in self.personality_fingerprint[t_num]['f']:
                        flags += 4
                    if "s" in self.personality_fingerprint[t_num]['f']:
                        flags += 2
                    if "f" in self.personality_fingerprint[t_num]['f']:
                        flags += 1
                    response['TCP'].flags = flags
                if 'o' in self.personality_fingerprint[t_num]:
                    o = self.personality_fingerprint[t_num]['o']

                if 'q' in self.personality_fingerprint[t_num]:
                    # quirk test haha they sure go 'beyond plus ultra' :D lmao
                    if 'r' in self.personality_fingerprint[t_num]['q']:
                        response['TCP'].reserved = 1
                    if 'u' in self.personality_fingerprint[t_num]['q']:
                        # TODO only if URG flag not set
                        response['TCP'].urgptr = 1

                if t_num == "t5" or t_num == "t6" or t_num == "t7":
                    # all sent to closed ports
                    if 'ci' in self.personality_fingerprint.seq:
                        ci = SessionManager.getInstance().getValue(dst_ip, 'seq', 'ci')
                        response['IP'].id = ci

            if pac_num:
                # seq test
                if "1" not in pac_num and 'r' in self.personality_fingerprint.win and \
                        'n' == self.personality_fingerprint.win['r']:
                    return
                if 'ti' in self.personality_fingerprint.seq:
                    # TODO TEST, ti isnt poping up in fingerprint
                    ti = SessionManager.getInstance().getValue(dst_ip, 'seq', 'ti')
                    response['IP'].id = ti
                if 'sp' in self.personality_fingerprint.seq:
                    # TODO conflict w/ t1.s
                    if not t_num:
                        pass
                        #sp = SessionManager.getInstance().getValue(dst_ip, 'seq', 'sp')
                        #response['IP'].id = sp

                '''
                if 'ss' in self.personality_fingerprint.seq:
                    ss = SessionManager.getInstance().getValue(dst_ip, 'seq', 'ss')
                    response['IP'].id = ss
                '''
                #very few prints dont have w or o (e.g. 3Com SuperStack 3 Switch 3870)
                # win test
                if "w"+pac_num in self.personality_fingerprint.win:
                    # account 0|ffff
                    win_size = self.personality_fingerprint.win["w"+pac_num].split('|')[0]
                    response['TCP'].window = int(win_size, 16)
                # ops test
                if "o"+pac_num in self.personality_fingerprint.ops:
                    o = self.personality_fingerprint.ops["o"+pac_num]

            # Publish once
            if not (is_nmap or is_sv or pac_num or t_num) and not bool(server_packet):
                is_open_port = False
                for service_data in self.services_string:
                    if str(sport)+",tcp," in service_data:
                        is_open_port = True
                        break
                if is_open_port:
                    self.publish(Event(EventTypes.TCPOpenHit, dst_ip))
                else:
                    self.publish(Event(EventTypes.TCPHit, dst_ip))

            if not (pac_num or t_num):
                #this is a legit request, let session manager call w/ it if it wants
                print('Dont care...')
                # TODO if im getting traffic from one ip to many different ports... publish
                return server_packet

            try:
                if o:
                    response['TCP'].options = self.cache[o]
            except UnboundLocalError:
                pass

            '''if t_num:
                if 'rd' in self.personality_fingerprint[t_num]:
                    if not self.personality_fingerprint[t_num]['rd'] == 0:
                        # TODO need an example
                        # TODO build database of cracked chksums
                        # error message in reset packet -rd is crc32 chksum of err message
                        crc32 = self.personality_fingerprint[t_num]['rd']
                        response = response/crc32'''

            # print("SENDING TCP RESPONSE:", response.summary())

            if SessionManager.getInstance().is_android:
                ether = Ether(src=packet['Ether'].dst, dst=packet['Ether'].src, type=0x800)
                sendp(ether/response, iface=self.interfaces[0])
            else:
                send(response, verbose=0)
            return None
        except Exception as ee:
            print(ee)
            traceback.print_exc()

    def handleUDP(self, packet):
        '''
        U1 PROB HAS STATIC IP.ID VALUE of 0x1042!!!
        u1.r = responded
        us1.df = dont frag
        u1.t = ip.ttl
        u1.tg = ip.ttl guess

        u1.ipl = total len of unreachable udp response
        u1.ripl = If len(IPerror) == packet[ip], g
        u1.un = last 4 bytes of ICMP header (usually 0)
        u1.rid = If IPerror.id == packet[ip].id, g, else exact value stored
                 some OS flip the bits to 0x4210
        u1.ripck = If IPerror.chksum = packet[ip].chksum, g, if zero, z, else i (invalid)
        u1.ruck = If UDPerror.chksum = packet[udp].chksum, g, else stored
        u1.rud = if Raw.load = packet[raw].load (or zero len?), g, else i (invalid)

        '''

        #print("IN UDP :", packet.summary())
        response = None
        dst_ip = packet['IP'].src
        my_ip = packet['IP'].dst
        port_dst = packet['UDP'].sport
        port_src = packet['UDP'].dport

        # Publish

        if str(packet['IP'].id) == str(0x1042):  # u1 probe
            print('UDP U1 PROBE')
            self.publish(Event(EventTypes.UDPScan, dst_ip))

        # UDP doesnt have many attributes like tcp, so it makes it harder to identify
        # Using nmap-payloads to help identify
        else:
            found = False
            try:
                if str(packet.load)[2:-1].startswith(r"help\r\n\r\n") or \
                        str(packet.load)[2:-1].lower() == r'\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00 ckaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00\x00!\x00\x01':
                    # TODO I could read all the udp packets from the service-probe file...
                    self.publish(Event(EventTypes.ServiceVersionScanUDP, dst_ip))
                    found = True
                elif port_src in self.udp_payloads:
                    str_payload = str(packet[3:])[2:-1].lower()
                    if str_payload in self.udp_payloads[port_src]:
                        self.publish(Event(EventTypes.UDPScan, dst_ip+",payload:"+str_payload))
                        found = True
                    else:  # Try as bytes/paresed
                        for load in self.udp_payloads[port_src]:
                            load_decode = codecs.decode(load, 'unicode_escape')
                            latin = str(load_decode.encode("latin"))[2:-1].lower()
                            print("COMPARE1:",latin)
                            print("COMPARE2:",str_payload)
                            dummy_packet = Ether()/IP()/UDP()/latin
                            if str_payload == latin or dummy_packet[3:] == packet[3:]:
                                self.publish(Event(EventTypes.UDPScan, dst_ip+",PARSED_payload:"+str_payload))
                                found = True
                            else:
                                # Check if padding is problem
                                remove_normal_load = str_payload[len(latin):].replace(r"\x00","")
                                if not len(remove_normal_load):
                                    print("SOLVED!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", remove_normal_load)
                                    self.publish(Event(EventTypes.UDPScan, dst_ip + ",Padded_payload:" + str_payload))
                                    found = True

                elif packet['UDP'].len == 8 and packet['IP'].flags == 0:
                    if packet.load == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                        self.publish(Event(EventTypes.UDPScan, dst_ip+",NORMAL_payload:"+str(packet.load)))
                        found = True
            except AttributeError:
                pass
            except Exception as e:
                print("PAYLOAD_EXCEPTION:",e)
                traceback.print_exc()
            if not found:
                for service_data in self.services_string:
                    if str(port_src) + ",udp," in service_data:
                        self.publish(Event(EventTypes.UDPOpenHit, dst_ip))
                        # TODO catch -sV probes?
                        #if dst_ip == "192.168.1.215":
                        #    packet.show()
                        # Let Service Spoofer handle it
                        return
                self.publish(Event(EventTypes.UDPHit, dst_ip))

        if 'r' in self.personality_fingerprint.u1 and self.personality_fingerprint.u1['r'] == 'n':
            # Do not respond trololol
            return

        # if we want an closed port...
        icmp = ICMP(type=3, code=3)
        if 'un' in self.personality_fingerprint.u1:
            if not self.personality_fingerprint.u1['un'] == "0":
                # the last byte in a UDPerror is normally 0, but sometimes it not
                # scapy bug? 'nexthopmtu' uses this instead of the 'unused' variable haha
                # beware in future updates
                icmp = ICMP(type=3, code=3, nexthopmtu=int(self.personality_fingerprint.u1['un'], 16))
        try:
            # Init packet
            ip = packet['IP']
            udp = packet['UDP']
            response = IP(src=my_ip, dst=dst_ip, proto=1) / icmp / \
                IPerror(version=ip.version, ihl=ip.ihl, tos=ip.tos, len=ip.len, id=ip.id, flags=ip.flags,
                        frag=ip.frag, ttl=ip.ttl, proto=ip.proto, chksum=ip.chksum, src=ip.src, dst=ip.dst) / \
                UDPerror(dport=udp.dport, sport=udp.sport, len=udp.len, chksum=udp.chksum)
            try:
                response = response / Raw(load=packet['Raw'].load)
            except:
                pass


            # APPLY FINGERPRINT

            if 't' in self.personality_fingerprint.u1:
                session_val = SessionManager.getInstance().getValue(dst_ip, "u1", "t")
                #print('TTL session val:', session_val, type(session_val))
                try:
                    ttl = int(session_val, 16)
                except TypeError:
                    ttl = session_val
                # TODO nmap expects some values over 0x100, so needs fixing
                # this is to patch an error
                response['IP'].ttl = ttl if ttl <= 255 else 255

            try:
                if 'ipl' in self.personality_fingerprint.u1:
                    ipl = int(self.personality_fingerprint.u1['ipl'], 16)
                    if len(response) > ipl:
                        response['Raw'].load = response['Raw'].load[:-len(response)-ipl]
                    elif len(response) < ipl:
                        # eg Novatel MiFi 4620L WAP hahaha (learning this at 3am on a Sun morning / Sat night lmao)
                        #print("Need to add bytes:", )
                        response['Raw'].load = response['Raw'].load + response['Raw'].load[:(ipl-len(response))]
                    # YASSSSSSS :D first confirmable success xD
                    # An other bites one the dust
            except IndexError:
                pass

            if 'ripck' in self.personality_fingerprint.u1:
                if self.personality_fingerprint.u1['ripck'] == "i":
                    response['IPerror'].chksum += 1
                elif self.personality_fingerprint.u1['ripck'] == "z":
                    response['IPerror'].chksum = 0

            if 'ruck' in self.personality_fingerprint.u1:
                if not self.personality_fingerprint.u1['ruck'] == "g":
                    response['UDPerror'].chksum = int(self.personality_fingerprint.u1['ruck'], 16)

            try:
                if 'rud' in self.personality_fingerprint.u1:
                    if not self.personality_fingerprint.u1['rud'] == "g":
                        response['Raw'].load = b'B' + response['Raw'].load[1:]
            except IndexError:
                pass

            if 'rid' in self.personality_fingerprint.u1:
                if not self.personality_fingerprint.u1['rid'] == "g":
                    response['IPerror'].id = int(self.personality_fingerprint.u1['rid'].split("-")[0], 16)

            if 'ripl' in self.personality_fingerprint.u1:
                if not self.personality_fingerprint.u1['ripl'] == "g":
                    response['IPerror'].len = int(self.personality_fingerprint.u1['ripl'], 16)

            if 'df' in self.personality_fingerprint.u1:
                response['IP'].flags = 2 if self.personality_fingerprint.u1['df'] == 'y' else 0

            # TODO verify t and tg values...

            # Done
            if str(packet['IP'].id) == str(0x1042):
                #print("OUT UDP:", response.summary())
                response.show2(dump=True)

            if SessionManager.getInstance().is_android:
                ether = Ether(src=packet['Ether'].dst, dst=packet['Ether'].src, type=0x800)
                sendp(ether/response, iface=self.interfaces[0])
            else:
                send(response, verbose=0)
        except Exception as ee:
            print(ee)
            traceback.print_exc()
        #print('done UDP handle')

    def __str__(self):
        return str(self.personality_fingerprint)


def scpNmap(spoofer, verbose):
    stamp = str(time.time())
    requests = ['nmap 11.0.0.20 -vv -O -p 90,91 -sUT --max-os-tries 1 -oN /root/tests/results/stamp_' + stamp,
                'sshpass -p toor scp /root/tests/results/stamp_' + stamp + ' 11.0.0.20:/root/tests/results/']
    w = open('/root/tests/requests/stamp-' + stamp, 'w')
    for request in requests:
        w.write(request + "\n")
    w.close()
    os.system("sshpass -p toor scp /root/tests/requests/stamp-" + stamp + " 11.0.0.10:/root/tests/requests/")

    # wait for results
    while not os.path.exists('/root/tests/results/stamp_' + stamp):
        time.sleep(1)
    if verbose:
        print('results are in!')
        f = Fingerprint(scan_text=open('/root/tests/results/stamp_' + stamp, 'r').read())
        print("****************************")
        print(f)
        print("****************************")
        spoofer.personality_fingerprint.compareFingerprint(f)
        spoofer.stop()


if __name__ == '__main__':
    # SO ssh wont work, consistantly getting different results when doing nmap via ssh vs manually e.e
    # Turns out, the first scan comes out weird..., think sniffing first packets takes
    # a while to init fd maybe.  TODO fix this - first scan is important

    spoofer = OsSpoofer(['eth0'], "Telekom Speedport W921V wireless DSL modem", [22, 80])
    # my favs haha
    #"Oracle JRockit Java virtual machine"
    #Phoenix Contact ILC 350 PN control system
    #Telekom Speedport W921V wireless DSL modem

    #"OpenBox S10 set-top box" - un (this one was tough)
    #"Novatel MiFi 4620L WAP" -rud and ipl
    #"Omron ITNV-EIS01 automation controller" - ripl and rid
    print(str(spoofer))
    spoofer.start()
    time.sleep(1)

    # Nmap SCP Test
    #'''
    scpNmap(spoofer, False)
    time.sleep(2)
    scpNmap(spoofer, True)
    #'''

    # Normal usage
    '''
    while 1:
        time.sleep(1)
    spoofer.stop()
    # '''

    '''
    # Test nmap os db parsing
    w = open('test.txt', 'w+')
    for i in range(5652+2):
        s = Fingerprint(i)
        print(str(i)+","+s.name+"\n", end="")
        w.write(str(i)+","+s.name+"\n")
    w.close()
    #'''


'''
Notes:
- Maybe some nmap fingerprint in the db are outdated... For the winXp fingerprint in the db,
  the u1() test does not have the r=y value.  It is implied, but not there.  The db could also 
  have small differences from the real scans.
  - Correction, nmap knows about this - its something to do w/ how u1 is usually dropped
- So I'm tyring to have the responding fingerprint have a u1.T value be "7b-85",
  so Im alternating between the two values, but nmap only chooses one of the value - this might be fine....
  but im not sure...
'''
