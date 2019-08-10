import os
from Abstract.Subscriber import Subscriber
from Event import *
from SessionManager import SessionManager
from datetime import datetime

# Role: track severity of an attacker, white/blacklist ips,
#       log scans, store user preferences (security level)
# Should be in real time.... but going to do on startup for now

# TODO save black_list to a file? (ip + network) and restore?


class IDS(Subscriber):
    def __init__(self, log_dir, security_level, white_list=[], black_list=[]):
        self.log_dir = log_dir
        self.security_level = security_level
        if self.security_level > 1:
            self.security_threshold = (self.security_level-1) * Event.scale_difference * 10  # TODO play with this value - find a good range
        else:
            self.security_threshold = None
        self.ip_map = {}  # IP to security_level
        # e.g. self.ip_map[ip] = dictionary with EventTypes names as key
        #      self.ip_map[ip]['TCPHit'] = [2,2] # an array with two values,
        #      the first being the occurrences of the event and the second being the sum of its weight
        self.white_list = white_list
        self.black_list = black_list
        if not self.log_dir[-1] == '/':
            self.log_dir += '/'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        if SessionManager.getInstance().is_android:
            self.iptables = '/system/bin/iptables'
        else:
            self.iptables = 'iptables'
        # TODO abstract/centralize iptables command path to SessionManger
        self.rules = []

    def clearIptables(self):
        base = self.iptables + " -D "
        for command in self.rules:
            os.system(base + command)
        self.rules.clear()

    def tryBlackList(self, ip):
        if ip in self.black_list:
            return
        total = 0
        for key in self.ip_map[ip]:
            total += self.ip_map[ip][key][1] * Event.scale_difference
        if total > self.security_threshold:
            self.black_list.append(ip)
            print('BLACK_LIST: '+ip)
            #base = self.iptables + " -I "
            #commands = ["INPUT -s "+ip+("" if "/" not in ip else "/32")+" -j DROP",
            #            "OUTPUT -d "+ip+("" if "/" not in ip else "/32")+" -j DROP"]
            #for command in commands:
            #    if command not in os.popen(self.iptables+"-save").read():
            #        self.rules.append(command)
            #        os.system(base+command)

    def tryWhiteList(self, ip):
        # Would this ever happen?
        # A host cant/should be able to send traffic to make you trust them again...
        pass

    def updateIpMap(self, event):
        ip = event.data.split(',')[0]
        if ip in self.white_list:
            return
        if ip not in self.ip_map:
            self.ip_map[ip] = {}
            for e_type in EventTypes:
                self.ip_map[ip][e_type.name] = [0, 0]
        self.ip_map[ip][event.event_type] = [self.ip_map[ip][event.event_type][0]+1,
                                             self.ip_map[ip][event.event_type][1]+event.weight]
        print("NEW WEIGHT:", ip, self.ip_map[ip])
        # Update ip rules (white/black list)

    def notify(self, event):
        ip = event.data.split(',')[0]
        if ip in self.white_list:
            return
        print('Got IDS event:', event)
        w = open(self.log_dir + event.event_type+'.log', 'a+')
        w.write(str(datetime.now())+"="+event.data+"\n")
        w.close()
        #TODO FOR TESTING
        self.updateIpMap(event)
        #TODO FOR TESTING
        if self.security_threshold:
            self.updateIpMap(event)
            self.tryBlackList(ip)
            self.tryWhiteList(ip)


'''
Notes:
These test were done with port 90 spoofed with tcp and with OS spoofer id 4000
- nmap    (interesting how noisy nmap is) 
  {'GenericNmapScan': [0, 0], 'ServiceVersionScan': [0, 0], 'OSScan': [0, 0], 'UDPScan': [0, 0], 'TCPScan': [0, 0], 'ICMPScan': [0, 0], 'UDPHit': [0, 0], 'TCPHit': [7, 7], 'ICMPHit': [0, 0]}
- nmap -p 90,91 
  {'GenericNmapScan': [0, 0], 'ServiceVersionScan': [0, 0], 'OSScan': [0, 0], 'UDPScan': [0, 0], 'TCPScan': [0, 0], 'ICMPScan': [0, 0], 'UDPHit': [0, 0], 'TCPHit': [1, 1], 'ICMPHit': [0, 0]}
- nmap -sV 
  {'GenericNmapScan': [0, 0], 'ServiceVersionScan': [1, 3], 'OSScan': [0, 0], 'UDPScan': [0, 0], 'TCPScan': [0, 0], 'ICMPScan': [0, 0], 'UDPHit': [0, 0], 'TCPHit': [10, 10], 'ICMPHit': [0, 0]}
- nmap -sV -p 90,91 
  {'GenericNmapScan': [0, 0], 'ServiceVersionScan': [1, 3], 'OSScan': [0, 0], 'UDPScan': [0, 0], 'TCPScan': [0, 0], 'ICMPScan': [0, 0], 'UDPHit': [0, 0], 'TCPHit': [2, 2], 'ICMPHit': [0, 0]}
- nmap -O
  {'GenericNmapScan': [0, 0], 'ServiceVersionScan': [0, 0], 'OSScan': [2, 6], 'UDPScan': [7, 21], 'TCPScan': [0, 0], 'ICMPScan': [2, 6], 'UDPHit': [0, 0], 'TCPHit': [30, 30], 'ICMPHit': [0, 0]}
- nmap -O -p 90,91
  {'GenericNmapScan': [0, 0], 'ServiceVersionScan': [0, 0], 'OSScan': [2, 6], 'UDPScan': [6, 18], 'TCPScan': [0, 0], 'ICMPScan': [5, 15], 'UDPHit': [0, 0], 'TCPHit': [25, 25], 'ICMPHit': [0, 0]}
- nmap -O -sU
  {'GenericNmapScan': [0, 0], 'ServiceVersionScan': [0, 0], 'OSScan': [0, 0], 'UDPScan': [1007, 3021], 'TCPScan': [0, 0], 'ICMPScan': [2, 6], 'UDPHit': [0, 0], 'TCPHit': [0, 0], 'ICMPHit': [0, 0]}
- nmap -O -sV
  {'GenericNmapScan': [0, 0], 'ServiceVersionScan': [1, 3], 'OSScan': [2, 6], 'UDPScan': [8, 24], 'TCPScan': [0, 0], 'ICMPScan': [2, 6], 'UDPHit': [0, 0], 'TCPHit': [31, 31], 'ICMPHit': [0, 0]}
- nmap -O -sV -p 90,91
  {'GenericNmapScan': [0, 0], 'ServiceVersionScan': [1, 3], 'OSScan': [2, 6], 'UDPScan': [8, 24], 'TCPScan': [0, 0], 'ICMPScan': [5, 15], 'UDPHit': [0, 0], 'TCPHit': [26, 26], 'ICMPHit': [0, 0]}



-sV unique packet
###[ Ethernet ]### 
  dst       = 94:de:80:7a:63:bf
  src       = 94:65:2d:2c:81:01
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 60
     id        = 28855
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x44eb
     src       = 192.168.1.215
     dst       = 192.168.1.242
     \options   \
###[ TCP ]### 
        sport     = 38726
        dport     = 90
        seq       = 398788415
        ack       = 0
        dataofs   = 10
        reserved  = 0
        flags     = S
        window    = 64240
        chksum    = 0x948a
        urgptr    = 0
        options   = [('MSS', 1460), ('SAckOK', b''), ('Timestamp', (87914376, 0)), ('NOP', None), ('WScale', 8)]

'''
